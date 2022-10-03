use async_trait::async_trait;
use ipnet::AddrParseError;
use regex::Regex;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::{collections::HashMap, net::IpAddr, sync::Arc};
use std::{fmt, net};
use tower::ServiceExt;
use trust_dns_proto::op;
use url::Url;

use crate::{common::trie, config::def::DNSMode, Error};

mod dns_client;
mod fakeip;
mod filters;
mod resolver;

use crate::dns::dns_client::DNSNetMode;
pub use resolver::ClashResolver;
pub use resolver::Resolver;

#[async_trait]
pub trait Client: Sync + Send {
    async fn exchange(&mut self, msg: &op::Message) -> Result<op::Message, Error>;
}

type ThreadSafeDNSClient = Arc<futures::lock::Mutex<dyn Client>>;

#[derive(Clone, Debug)]
pub struct NameServer {
    net: DNSNetMode,
    address: String,
    interface: Option<String>,
}

struct FallbackFilter {
    geo_ip: bool,
    geo_ip_code: String,
    ip_cidr: Option<Vec<ipnet::IpNet>>,
    domain: Vec<String>,
}

pub struct Config {
    enable: bool,
    ipv6: bool,
    nameserver: Vec<NameServer>,
    fallback: Vec<NameServer>,
    fallback_filter: FallbackFilter,
    listen: String,
    enhance_mode: DNSMode,
    default_nameserver: Vec<NameServer>,
    fake_ip_range: Option<fakeip::FakeDns>,
    hosts: Option<trie::StringTrie<IpAddr>>,
    nameserver_policy: HashMap<String, NameServer>,
}

impl Config {
    pub fn parse_nameserver(servers: &Vec<String>) -> Result<Vec<NameServer>, Error> {
        let mut nameservers = vec![];

        for (i, server) in servers.into_iter().enumerate() {
            let mut server = server.clone();

            if !server.contains("://") {
                server = "udp://".to_owned() + &server;
            }
            let url = Url::parse(&server).map_err(|_x| {
                Error::InvalidConfig(format!("invalid dns server: {}", server.as_str()))
            })?;

            let host = url.host_str().expect("dns host must be valid");

            let iface = url.fragment();
            let addr: String;
            let net: &str;

            match url.scheme() {
                "udp" => {
                    addr = Config::host_with_default_port(&host, "53")?;
                    net = "UDP";
                }
                "tcp" => {
                    addr = Config::host_with_default_port(&host, "53")?;
                    net = "TCP";
                }
                "tls" => {
                    addr = Config::host_with_default_port(&host, "853")?;
                    net = "DoT";
                }
                "https" => {
                    addr = format!("https://{}{}", &host, url.path());
                    net = "DoH";
                }
                "dhcp" => {
                    unimplemented!();
                }
                _ => {
                    return Err(Error::InvalidConfig(String::from(format!(
                        "DNS nameserver [{}] unsupported scheme: {}",
                        i,
                        url.scheme()
                    ))));
                }
            }

            nameservers.push(NameServer {
                address: addr,
                net: net.parse()?,
                interface: iface.map(String::from),
            });
        }

        Ok(nameservers)
    }

    pub fn parse_nameserver_policy(
        policy_map: &HashMap<String, String>,
    ) -> Result<HashMap<String, NameServer>, Error> {
        let mut policy = HashMap::new();

        for (domain, server) in policy_map {
            let nameservers = Config::parse_nameserver(&vec![server.to_owned()])?;

            let (_, valid) = trie::valid_and_split_domain(&domain);
            if !valid {
                return Err(Error::InvalidConfig(format!(
                    "DNS ResolverRule invalid domain: {}",
                    &domain
                )));
            }
            policy.insert(domain.into(), nameservers[0].clone());
        }
        Ok(policy)
    }

    pub fn parse_fallback_ip_cidr(ipcidr: &Vec<String>) -> anyhow::Result<Vec<ipnet::IpNet>> {
        let mut output = vec![];

        for (_i, ip) in ipcidr.iter().enumerate() {
            let net: ipnet::IpNet = ip
                .parse()
                .map_err(|x: AddrParseError| Error::InvalidConfig(x.to_string()))?;
            output.push(net);
        }

        Ok(output)
    }

    pub fn parse_hosts(
        hosts_mapping: &HashMap<String, String>,
    ) -> anyhow::Result<trie::StringTrie<IpAddr>> {
        let mut tree = trie::StringTrie::new();
        tree.insert(
            "localhost",
            Arc::new("127.0.0.1".parse::<IpAddr>().unwrap()),
        );

        for (host, ip_str) in hosts_mapping.into_iter() {
            let ip = ip_str.parse::<IpAddr>()?;
            tree.insert(host.as_str(), Arc::new(ip));
        }

        Ok(tree)
    }

    pub fn host_with_default_port(host: &str, port: &str) -> Result<String, Error> {
        let has_port_suffix = Regex::new(r":\d+$").unwrap();

        if has_port_suffix.is_match(&host) {
            Ok(host.into())
        } else {
            Ok(format!("{}:{}", host, port))
        }
    }
}

impl TryFrom<crate::config::def::Config> for Config {
    type Error = Error;

    fn try_from(value: crate::def::Config) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&crate::config::def::Config> for Config {
    type Error = Error;

    fn try_from(c: &crate::config::def::Config) -> Result<Self, Self::Error> {
        let dc = &c.dns;
        if dc.enable && dc.nameserver.len() == 0 {
            return Err(Error::InvalidConfig(String::from(
                "dns enabled, no nameserver specified",
            )));
        }

        let nameservers = Config::parse_nameserver(&dc.nameserver)?;
        let fallback = Config::parse_nameserver(&dc.fallback)?;
        let nameserver_policy = Config::parse_nameserver_policy(&dc.nameserver_policy)?;

        if dc.default_nameserver.len() == 0 {
            return Err(Error::InvalidConfig(String::from(
                "default nameserver empty",
            )));
        }

        for ns in &dc.default_nameserver {
            let _ = ns.parse::<IpAddr>().map_err(|_| {
                Error::InvalidConfig(String::from("default dns must be ip address"))
            })?;
        }
        let default_nameserver = Config::parse_nameserver(&dc.default_nameserver)?;

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
                        .map_err(|_| Error::InvalidConfig(String::from("invalid fake ip range")))?;

                    Some(fakeip::FakeDns::new(fakeip::Opts {
                        ipnet,
                        host: if dc.fake_ip_filter.len() != 0 {
                            let mut host = trie::StringTrie::new();
                            for domain in dc.fake_ip_filter.iter() {
                                host.insert(domain.as_str(), Arc::new(true));
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
            hosts: if dc.user_hosts && c.hosts.len() > 0 {
                Config::parse_hosts(&c.hosts).ok()
            } else {
                None
            },
            nameserver_policy,
        })
    }
}

impl From<crate::config::def::FallbackFilter> for FallbackFilter {
    fn from(c: crate::config::def::FallbackFilter) -> Self {
        let ipcidr = Config::parse_fallback_ip_cidr(&c.ip_cidr);
        Self {
            geo_ip: c.geo_ip,
            geo_ip_code: c.geo_ip_code,
            ip_cidr: ipcidr.ok(),
            domain: c.domain,
        }
    }
}
