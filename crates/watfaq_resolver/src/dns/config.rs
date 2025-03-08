use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use ipnet::AddrParseError;
use regex::Regex;

use url::Url;
use watfaq_dns::DNSListenAddr;
use watfaq_error::{ErrContext, Result, anyhow};
use watfaq_types::{DNSMode, StringTrie};

use super::dns_client::DNSNetMode;

#[derive(Clone, Debug)]
pub struct NameServer {
    pub net: DNSNetMode,
    pub address: String,
    pub opts: Option<String>,
}
impl Display for NameServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}#{:?}", self.net, self.address, self.opts)
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
pub struct DnsConfig {
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
    pub hosts: Option<StringTrie<IpAddr>>,
    pub nameserver_policy: HashMap<String, NameServer>,
}

impl DnsConfig {
    pub fn parse_nameserver(servers: &[String]) -> Result<Vec<NameServer>> {
        let mut nameservers = vec![];

        for (i, server) in servers.iter().enumerate() {
            let mut server = server.clone();

            if !server.contains("://") {
                server = "udp://".to_owned() + &server;
            }
            let url = Url::parse(&server)
                .with_context(|| format!("invalid dns server: {}", server))?;

            let host = url
                .host_str()
                .ok_or_else(|| anyhow!("dns host must be valid"))?;

            let addr: String;
            let net: &str;

            match url.scheme() {
                "udp" => {
                    addr = DnsConfig::host_with_default_port(host, "53")?;
                    net = "UDP";
                }
                "tcp" => {
                    addr = DnsConfig::host_with_default_port(host, "53")?;
                    net = "TCP";
                }
                "tls" => {
                    addr = DnsConfig::host_with_default_port(host, "853")?;
                    net = "DoT";
                }
                "https" => {
                    addr = DnsConfig::host_with_default_port(host, "443")?;
                    net = "DoH";
                }
                "dhcp" => {
                    addr = host.to_string();
                    net = "DHCP";
                }
                _ => {
                    return Err(anyhow!(
                        "DNS nameserver [{}] unsupported scheme: {}",
                        i,
                        url.scheme()
                    ));
                }
            }

            let net = net.parse()?;
            nameservers.push(NameServer {
                address: addr,
                net,
                opts: url.fragment().map(|v| v.to_string()),
            });
        }

        Ok(nameservers)
    }

    pub fn parse_nameserver_policy(
        policy_map: &HashMap<String, String>,
    ) -> Result<HashMap<String, NameServer>> {
        let mut policy = HashMap::new();

        for (domain, server) in policy_map {
            let nameservers = DnsConfig::parse_nameserver(&[server.to_owned()])?;
            // TODO ugly
            let (_, valid) = StringTrie::<()>::valid_and_split_domain(domain);
            if !valid {
                return Err(anyhow!("DNS ResolverRule invalid domain: {}", &domain));
            }
            policy.insert(domain.into(), nameservers[0].clone());
        }
        Ok(policy)
    }

    pub fn parse_fallback_ip_cidr(ipcidr: &[String]) -> Result<Vec<ipnet::IpNet>> {
        let mut output = vec![];

        for ip in ipcidr.iter() {
            let net: ipnet::IpNet = ip.parse()?;
            output.push(net);
        }

        Ok(output)
    }

    pub fn parse_hosts(
        hosts_mapping: &HashMap<String, String>,
    ) -> Result<StringTrie<IpAddr>> {
        let mut tree = StringTrie::new();
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

    pub fn host_with_default_port(host: &str, port: &str) -> Result<String> {
        let has_port_suffix = Regex::new(r":\d+$").unwrap();

        if has_port_suffix.is_match(host) {
            Ok(host.into())
        } else {
            Ok(format!("{}:{}", host, port))
        }
    }
}
