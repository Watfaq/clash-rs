use ipnet::IpNet;
use regex::Regex;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};
use url::Url;

use crate::{common::trie, config::def::DNSMode, Error};

mod dns_client;
mod fakeip;

#[derive(Clone)]
pub struct NameServer {
    net: String,
    address: String,
    interface: Option<String>,
}

pub struct DNS {
    enable: bool,
    ipv6: bool,
    nameserver: Vec<NameServer>,
    fallback: Vec<NameServer>,
    fallback_filter: FallbackFilter,
    listen: String,
    enhance_mode: DNSMode,
    default_nameserver: Vec<NameServer>,
    fake_ip_range: Option<fakeip::FakeDns>,
    hosts: Option<trie::DomainTrie>,
    nameserver_policy: HashMap<String, NameServer>,
}

lazy_static! {
    static ref HAS_PORT_SUFFIX: Regex = Regex::new(r":\d+$").unwrap();
}

impl DNS {
    pub fn parse_nameserver(servers: &Vec<String>) -> anyhow::Result<Vec<NameServer>> {
        let mut nameservers = vec![];

        for (i, server) in servers.into_iter().enumerate() {
            let mut server = server.clone();

            if !server.contains("://") {
                server = "udp://".to_owned() + &server;
            }
            let url = Url::parse(&server)?;
            let host = url.host_str().expect("dns host must be valid");

            let iface = url.fragment();
            let addr: String;
            let net: &str;

            match url.scheme() {
                "udp" => {
                    addr = DNS::host_with_default_port(&host, "53")?;
                    net = "";
                }
                "tcp" => {
                    addr = DNS::host_with_default_port(&host, "53")?;
                    net = "tcp";
                }
                "tls" => {
                    addr = DNS::host_with_default_port(&host, "853")?;
                    net = "tcp-tls";
                }
                "https" => {
                    addr = format!("https://{}{}", &host, url.path());
                    net = "https";
                }
                "dhcp" => {
                    addr = host.into();
                    net = "dhcp";
                }
                _ => {
                    return Err(anyhow!(
                        "DNS nameserver [{}] unsupported scheme: {}",
                        i,
                        url.scheme()
                    ))
                }
            }
            nameservers.push(NameServer {
                address: addr.into(),
                net: net.into(),
                interface: iface.map(String::from),
            });
        }

        Ok(nameservers)
    }

    pub fn parse_nameserver_policy(
        policy_map: &HashMap<String, String>,
    ) -> anyhow::Result<HashMap<String, NameServer>> {
        let mut policy = HashMap::new();

        for (domain, server) in policy_map {
            let nameservers = DNS::parse_nameserver(&vec![server.to_owned()])?;

            let (_, valid) = trie::valid_and_splic_domain(&domain);
            if !valid {
                return Err(anyhow!("DNS ResolverRule invalid domain: {}", &domain));
            }
            policy.insert(domain.into(), nameservers[0].clone());
        }
        Ok(policy)
    }

    pub fn parse_fallback_ip_cidr(ipcidr: &Vec<String>) -> anyhow::Result<Vec<ipnet::IpNet>> {
        let mut output = vec![];

        for (i, ip) in ipcidr.iter().enumerate() {
            let net: IpNet = ip.parse()?;
            output.push(net);
        }

        Ok(output)
    }

    pub fn parse_hosts(
        hosts_mapping: &HashMap<String, String>,
    ) -> anyhow::Result<trie::DomainTrie> {
        let mut tree = trie::StringTrie::new();
        Ok(tree)
    }

    pub fn host_with_default_port<'a>(host: &'a str, port: &str) -> anyhow::Result<String> {
        if HAS_PORT_SUFFIX.is_match(&host) {
            Ok(host.into())
        } else {
            Ok(format!("{}:{}", host, port))
        }
    }
}

impl TryFrom<&crate::config::def::Config> for DNS {
    type Error = Error;

    fn try_from(c: &crate::config::def::Config) -> Result<Self, Self::Error> {
        let dc = &c.dns;
        if dc.enable && dc.nameserver.len() == 0 {
            return Err(Error::InvalidConfig(
                anyhow!("dns enabled, no nameserver speficied").into(),
            ));
        }

        let nameservers = DNS::parse_nameserver(&dc.nameserver)?;
        let fallback = DNS::parse_nameserver(&dc.fallback)?;
        let nameserver_policy = DNS::parse_nameserver_policy(&dc.nameserver_policy)?;

        if dc.default_nameserver.len() == 0 {
            return Err(Error::InvalidConfig(
                anyhow!("default nameserver empty").into(),
            ));
        }

        for ns in &dc.default_nameserver {
            let _ = ns
                .parse::<IpAddr>()
                .map_err(|_| Error::InvalidConfig(anyhow!("default dns must be ip address")))?;
        }
        let default_nameserver = DNS::parse_nameserver(&dc.default_nameserver)?;

        Ok(Self {
            enable: dc.enable,
            ipv6: dc.ipv6,
            nameserver: nameservers,
            fallback,
            fallback_filter: dc.fallback_filter.clone().into(),
            listen: dc.listen.clone(),
            enhance_mode: dc.enhanced_mode.clone(),
            default_nameserver,
            fake_ip_range: match dc.enhanced_mode {
                DNSMode::FakeIP => {
                    let ipnet = dc
                        .fake_ip_range
                        .parse::<ipnet::IpNet>()
                        .map_err(|_| Error::InvalidConfig(anyhow!("invalid fake ip range")))?;

                    Some(fakeip::FakeDns::new(fakeip::Opts {
                        ipnet,
                        host: if dc.fake_ip_filter.len() != 0 {
                            let mut host = trie::DomainTrie::new();
                            for domain in dc.fake_ip_filter.iter() {
                                host.insert(domain.as_str(), Rc::new(true));
                            }
                            Some(host)
                        } else {
                            None
                        },
                        size: 1000,
                        persistence: c.profile.store_fake_ip,
                        db_path: None,
                    })?)
                }
                _ => None,
            },
            hosts: if dc.user_hosts && c.hosts.is_some() {
                DNS::parse_hosts(&c.hosts.as_ref().unwrap()).ok()
            } else {
                None
            },
            nameserver_policy: nameserver_policy,
        })
    }
}

struct FallbackFilter {
    geo_ip: bool,
    geo_ip_code: String,
    ip_cidr: Option<Vec<ipnet::IpNet>>,
    domain: Vec<String>,
}

impl From<crate::config::def::FallbackFilter> for FallbackFilter {
    fn from(c: crate::config::def::FallbackFilter) -> Self {
        let ipcidr = DNS::parse_fallback_ip_cidr(&c.ip_cidr);
        Self {
            geo_ip: c.geo_ip,
            geo_ip_code: c.geo_ip_code,
            ip_cidr: ipcidr.ok(),
            domain: c.domain,
        }
    }
}
