use async_trait::async_trait;
use ipnet::AddrParseError;
use regex::Regex;
use rustls::{Certificate, PrivateKey};
use std::fmt::Debug;
use std::io::BufReader;
use std::net::SocketAddr;
use std::{collections::HashMap, net::IpAddr, sync::Arc};
use trust_dns_proto::op;
use url::Url;

use crate::config::def::DNSListen;
use crate::{common::trie, config::def::DNSMode, Error};

mod dhcp;
mod dns_client;
mod dummy_keys;
mod fakeip;
mod filters;
mod helper;
pub mod resolver;
mod server;
mod system;

use crate::dns::dns_client::DNSNetMode;

pub use resolver::ClashResolver;
pub use resolver::Resolver;
pub use server::get_dns_listener;

use self::dummy_keys::{TEST_CERT, TEST_KEY};

#[macro_export]
macro_rules! dns_debug {
    ($($arg:tt)*) => {
        debug!(target: "dns", $($arg)*)
    };
}

#[macro_export]
macro_rules! dns_info {
    ($($arg:tt)*) => {
        info!(target: "dns", $($arg)*)
    };
}

#[macro_export]
macro_rules! dns_warn {
    ($($arg:tt)*) => {
        warn!(target: "dns", $($arg)*)
    };
}

#[async_trait]
pub trait Client: Sync + Send + Debug {
    // TODO: make this non mutable
    async fn exchange(&mut self, msg: &op::Message) -> anyhow::Result<op::Message>;
}

type ThreadSafeDNSClient = Arc<futures::lock::Mutex<dyn Client>>;

#[derive(Clone, Debug)]
pub struct NameServer {
    pub net: DNSNetMode,
    pub address: String,
    pub interface: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct FallbackFilter {
    geo_ip: bool,
    geo_ip_code: String,
    ip_cidr: Option<Vec<ipnet::IpNet>>,
    domain: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DoHConfig {
    certificate_and_key: (Vec<Certificate>, PrivateKey),
    dns_hostname: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DoTConfig {
    certificate_and_key: (Vec<Certificate>, PrivateKey),
}

#[derive(Clone, Debug, Default)]
pub struct DNSListenAddr {
    udp: Option<SocketAddr>,
    tcp: Option<SocketAddr>,
    doh: Option<(SocketAddr, DoHConfig)>,
    dot: Option<(SocketAddr, DoTConfig)>,
}

#[derive(Default)]
pub struct Config {
    enable: bool,
    ipv6: bool,
    nameserver: Vec<NameServer>,
    fallback: Vec<NameServer>,
    fallback_filter: FallbackFilter,
    listen: DNSListenAddr,
    enhance_mode: DNSMode,
    default_nameserver: Vec<NameServer>,
    fake_dns: Option<fakeip::FakeDns>,
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
                    addr = Config::host_with_default_port(&host, "443")?;
                    net = "DoH";
                }
                "dhcp" => {
                    addr = host.to_string();
                    net = "DHCP";
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
            listen: dc
                .listen
                .clone()
                .map(|l| match l {
                    DNSListen::Udp(u) => {
                        let addr = u.parse::<SocketAddr>().map_err(|_| {
                            Error::InvalidConfig(
                                format!("invalid dns udp listen address: {}", u).into(),
                            )
                        })?;
                        Ok(DNSListenAddr {
                            udp: Some(addr),
                            ..Default::default()
                        })
                    }
                    DNSListen::Multiple(map) => {
                        let mut udp = None;
                        let mut tcp = None;
                        let mut doh = None;
                        let mut dot = None;

                        for (k, v) in map {
                            let addr = v.parse::<SocketAddr>().map_err(|_| {
                                Error::InvalidConfig(
                                    format!("invalid DNS listen address: {} -> {}", k, v).into(),
                                )
                            })?;
                            match k.as_str() {
                                "udp" => udp = Some(addr),
                                "tcp" => tcp = Some(addr),
                                "doh" => {
                                    let mut buf_read: Box<dyn std::io::BufRead> =
                                        Box::new(BufReader::new(TEST_CERT.as_bytes()));
                                    let certs = rustls_pemfile::certs(&mut buf_read)
                                        .unwrap()
                                        .into_iter()
                                        .map(Certificate)
                                        .collect::<Vec<_>>();

                                    let mut buf_read: Box<dyn std::io::BufRead> =
                                        Box::new(BufReader::new(TEST_KEY.as_bytes()));
                                    let mut keys =
                                        rustls_pemfile::pkcs8_private_keys(&mut buf_read).unwrap();
                                    let c = DoHConfig {
                                        certificate_and_key: (certs, PrivateKey(keys.remove(0))),
                                        dns_hostname: Some("dns.example.com".to_owned()),
                                    };
                                    doh = Some((addr, c))
                                }
                                "dot" => {
                                    let mut buf_read: Box<dyn std::io::BufRead> =
                                        Box::new(BufReader::new(TEST_CERT.as_bytes()));
                                    let certs = rustls_pemfile::certs(&mut buf_read)
                                        .unwrap()
                                        .into_iter()
                                        .map(Certificate)
                                        .collect::<Vec<_>>();

                                    let mut buf_read: Box<dyn std::io::BufRead> =
                                        Box::new(BufReader::new(TEST_KEY.as_bytes()));
                                    let mut keys =
                                        rustls_pemfile::pkcs8_private_keys(&mut buf_read).unwrap();
                                    let c = DoTConfig {
                                        certificate_and_key: (certs, PrivateKey(keys.remove(0))),
                                    };
                                    dot = Some((addr, c))
                                }
                                _ => {
                                    return Err(Error::InvalidConfig(format!(
                                        "invalid dns listen address: {}",
                                        k
                                    )))
                                }
                            }
                        }

                        Ok(DNSListenAddr { udp, tcp, doh, dot })
                    }
                })
                .transpose()?
                .unwrap_or_default(),
            enhance_mode: dc.enhanced_mode.clone(),
            default_nameserver,
            fake_dns: match dc.enhanced_mode {
                DNSMode::FakeIp => {
                    let ipnet = dc
                        .fake_ip_range
                        .parse::<ipnet::IpNet>()
                        .map_err(|_| Error::InvalidConfig(String::from("invalid fake ip range")))?;

                    Some(fakeip::FakeDns::new(fakeip::Opts {
                        ipnet,
                        skipped_hostnames: if dc.fake_ip_filter.len() != 0 {
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
                let mut tree = trie::StringTrie::new();
                tree.insert(
                    "localhost",
                    Arc::new("127.0.0.1".parse::<IpAddr>().unwrap()),
                );
                Some(tree)
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
