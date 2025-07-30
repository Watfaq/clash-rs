use super::dns_client::DNSNetMode;
use crate::{
    Error,
    app::net::{OutboundInterface, get_interface_by_name, get_outbound_interface},
    common::trie,
    config::def::{DNSListen, DNSMode},
};
use ipnet::AddrParseError;
use regex::Regex;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use url::Url;
use watfaq_dns::{DNSListenAddr, DoH3Config, DoHConfig, DoTConfig};

#[derive(Clone, Debug)]
pub struct NameServer {
    pub net: DNSNetMode,
    pub address: String,
    pub interface: Option<OutboundInterface>,
}
impl Display for NameServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}#{:?}", self.net, self.address, self.interface,)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FallbackFilter {
    pub geo_ip: bool,
    pub geo_ip_code: String,
    pub ip_cidr: Option<Vec<ipnet::IpNet>>,
    pub domain: Vec<String>,
}

#[derive(Default)]
pub struct Config {
    pub enable: bool,
    pub ipv6: bool,
    pub nameserver: Vec<NameServer>,
    pub fallback: Vec<NameServer>,
    pub fallback_filter: FallbackFilter,
    pub listen: DNSListenAddr,
    pub enhance_mode: DNSMode,
    pub default_nameserver: Vec<NameServer>,
    pub fake_ip_range: ipnet::IpNet,
    pub fake_ip_filter: Vec<String>,
    pub store_fake_ip: bool,
    pub store_smart_stats: bool,
    pub hosts: Option<trie::StringTrie<IpAddr>>,
    pub nameserver_policy: HashMap<String, NameServer>,
}

impl Config {
    pub fn parse_nameserver(servers: &[String]) -> Result<Vec<NameServer>, Error> {
        let mut nameservers = vec![];

        for (i, server) in servers.iter().enumerate() {
            let mut server = server.clone();

            if !server.contains("://") {
                server = "udp://".to_owned() + &server;
            }
            let url = Url::parse(&server).map_err(|_x| {
                Error::InvalidConfig(format!(
                    "invalid dns server: {}",
                    server.as_str()
                ))
            })?;

            let host = url.host_str().expect("dns host must be valid");

            let iface = url.fragment();
            let addr: String;
            let net: &str;

            match url.scheme() {
                "udp" => {
                    addr = Config::host_with_default_port(host, "53")?;
                    net = "UDP";
                }
                "tcp" => {
                    addr = Config::host_with_default_port(host, "53")?;
                    net = "TCP";
                }
                "tls" => {
                    addr = Config::host_with_default_port(host, "853")?;
                    net = "DoT";
                }
                "https" => {
                    addr = Config::host_with_default_port(host, "443")?;
                    net = "DoH";
                }
                "dhcp" => {
                    addr = host.to_string();
                    net = "DHCP";
                }
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "DNS nameserver [{}] unsupported scheme: {}",
                        i,
                        url.scheme()
                    )));
                }
            }

            let net = net.parse()?;
            nameservers.push(NameServer {
                address: addr,
                net,
                interface: iface
                    .map(|x| match x {
                        "auto" => {
                            get_outbound_interface().ok_or(Error::InvalidConfig(
                                "DNS nameserver [auto] no outbound interface found"
                                    .into(),
                            ))
                        }
                        name => get_interface_by_name(name).ok_or(
                            Error::InvalidConfig(format!(
                                "DNS nameserver [{i}] invalid interface: {name}"
                            )),
                        ),
                    })
                    .transpose()?,
            });
        }

        Ok(nameservers)
    }

    pub fn parse_nameserver_policy(
        policy_map: &HashMap<String, String>,
    ) -> Result<HashMap<String, NameServer>, Error> {
        let mut policy = HashMap::new();

        for (domain, server) in policy_map {
            let nameservers = Config::parse_nameserver(&[server.to_owned()])?;

            let (_, valid) = trie::valid_and_split_domain(domain);
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

    pub fn parse_fallback_ip_cidr(
        ipcidr: &[String],
    ) -> anyhow::Result<Vec<ipnet::IpNet>> {
        let mut output = vec![];

        for ip in ipcidr.iter() {
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

        for (host, ip_str) in hosts_mapping.iter() {
            let ip = ip_str.parse::<IpAddr>()?;
            tree.insert(host.as_str(), Arc::new(ip));
        }

        Ok(tree)
    }

    pub fn host_with_default_port(host: &str, port: &str) -> Result<String, Error> {
        let has_port_suffix = Regex::new(r":\d+$").unwrap();

        if has_port_suffix.is_match(host) {
            Ok(host.into())
        } else {
            Ok(format!("{host}:{port}"))
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
        if dc.enable && dc.nameserver.is_empty() {
            return Err(Error::InvalidConfig(String::from(
                "dns enabled, no nameserver specified",
            )));
        }

        let nameservers = Config::parse_nameserver(&dc.nameserver)?;
        let fallback = Config::parse_nameserver(&dc.fallback)?;
        let nameserver_policy =
            Config::parse_nameserver_policy(&dc.nameserver_policy)?;

        if dc.default_nameserver.is_empty() {
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
            ipv6: c.ipv6 && dc.ipv6,
            nameserver: nameservers,
            fallback,
            fallback_filter: dc.fallback_filter.clone().into(),
            listen: dc
                .listen
                .clone()
                .map(|l| match l {
                    DNSListen::Udp(u) => {
                        let addr = u.parse::<SocketAddr>().map_err(|_| {
                            Error::InvalidConfig(format!(
                                "invalid dns udp listen address: {u}"
                            ))
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
                        let mut doh3 = None;
                        let mut dot = None;

                        for (k, v) in map {
                            match k.as_str() {
                                "udp" => {
                                    let addr = v
                                        .as_str()
                                        .ok_or(Error::InvalidConfig(format!(
                                            "invalid udp dns listen address - must \
                                             be string: {v:?}"
                                        )))?
                                        .parse::<SocketAddr>()
                                        .map_err(|_| {
                                            Error::InvalidConfig(format!(
                                                "invalid dns listen address: {v:?}"
                                            ))
                                        })?;
                                    udp = Some(addr)
                                }
                                "tcp" => {
                                    let addr = v
                                        .as_str()
                                        .ok_or(Error::InvalidConfig(format!(
                                            "invalid tcp dns listen address - must \
                                             be string: {v:?}"
                                        )))?
                                        .parse::<SocketAddr>()
                                        .map_err(|_| {
                                            Error::InvalidConfig(format!(
                                                "invalid dns listen address: {v:?}"
                                            ))
                                        })?;
                                    tcp = Some(addr)
                                }
                                "doh" => {
                                    let c =
                                        DoHConfig::deserialize(v).map_err(|x| {
                                            Error::InvalidConfig(format!(
                                                "invalid doh dns listen config: \
                                                 {x:?}"
                                            ))
                                        })?;

                                    doh = Some(c)
                                }
                                "dot" => {
                                    let c =
                                        DoTConfig::deserialize(v).map_err(|x| {
                                            Error::InvalidConfig(format!(
                                                "invalid dot dns listen config: \
                                                 {x:?}"
                                            ))
                                        })?;
                                    dot = Some(c)
                                }
                                "doh3" => {
                                    let c =
                                        DoH3Config::deserialize(v).map_err(|x| {
                                            Error::InvalidConfig(format!(
                                                "invalid doh3 dns listen config: \
                                                 {x:?}"
                                            ))
                                        })?;

                                    doh3 = Some(c)
                                }
                                _ => {
                                    return Err(Error::InvalidConfig(format!(
                                        "invalid dns listen address: {k}"
                                    )));
                                }
                            }
                        }

                        Ok(DNSListenAddr {
                            udp,
                            tcp,
                            doh,
                            dot,
                            doh3,
                        })
                    }
                })
                .transpose()?
                .unwrap_or_default(),
            enhance_mode: dc.enhanced_mode.clone(),
            default_nameserver,
            fake_ip_range: dc.fake_ip_range.parse::<ipnet::IpNet>().map_err(
                |_| Error::InvalidConfig(String::from("invalid fake ip range")),
            )?,
            fake_ip_filter: dc.fake_ip_filter.clone(),
            store_fake_ip: c.profile.store_fake_ip,
            store_smart_stats: c.profile.store_smart_stats,
            hosts: if dc.user_hosts && !c.hosts.is_empty() {
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
            geo_ip_code: c.geo_ip_code.to_lowercase(),
            ip_cidr: ipcidr.ok(),
            domain: c.domain,
        }
    }
}
