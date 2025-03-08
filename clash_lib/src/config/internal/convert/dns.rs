use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use serde::Deserialize;
use watfaq_dns::{DNSListenAddr, DoH3Config, DoHConfig, DoTConfig};
use watfaq_error::{ErrContext, Error, Result, anyhow};
use watfaq_resolver::DnsConfig as Config;
use watfaq_types::StringTrie;

use crate::config::DNSListen;

pub fn convert(def: &crate::config::def::Config) -> Result<Config> {
    let dc = &def.dns;
    if dc.enable && dc.nameserver.is_empty() {
        return Err(anyhow!("dns enabled, no nameserver specified"));
    }

    let nameservers = Config::parse_nameserver(&dc.nameserver)?;
    let fallback = Config::parse_nameserver(&dc.fallback)?;
    let nameserver_policy = Config::parse_nameserver_policy(&dc.nameserver_policy)?;

    if dc.default_nameserver.is_empty() {
        return Err(anyhow!("default nameserver empty"));
    }

    for ns in &dc.default_nameserver {
        let _ = ns
            .parse::<IpAddr>()
            .with_context(|| "default dns must be ip address")?;
    }
    let default_nameserver = Config::parse_nameserver(&dc.default_nameserver)?;

    Ok(Config {
        enable: dc.enable,
        ipv6: def.ipv6 && dc.ipv6,
        nameserver: nameservers,
        fallback,
        fallback_filter: dc.fallback_filter.clone().into(),
        listen: dc
            .listen
            .clone()
            .map(|l| match l {
                DNSListen::Udp(u) => {
                    let addr = u.parse::<SocketAddr>().with_context(|| {
                        format!("invalid dns udp listen address: {}", u)
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
                                    .ok_or_else(|| {
                                        anyhow!(
                                            "invalid udp dns listen address - must \
                                             be string: {:?}",
                                            v
                                        )
                                    })?
                                    .parse::<SocketAddr>()
                                    .with_context(|| {
                                        format!(
                                            "invalid dns listen address: {:?}",
                                            v
                                        )
                                    })?;
                                udp = Some(addr)
                            }
                            "tcp" => {
                                let addr = v
                                    .as_str()
                                    .ok_or_else(|| {
                                        anyhow!(
                                            "invalid tcp dns listen address - must \
                                             be string: {:?}",
                                            v
                                        )
                                    })?
                                    .parse::<SocketAddr>()
                                    .with_context(|| {
                                        format!(
                                            "invalid dns listen address: {:?}",
                                            v
                                        )
                                    })?;
                                tcp = Some(addr)
                            }
                            "doh" => {
                                let c = DoHConfig::deserialize(v)
                                    .context("invalid doh dns listen config")?;

                                doh = Some(c)
                            }
                            "dot" => {
                                let c = DoTConfig::deserialize(v)
                                    .context("invalid dot dns listen config")?;
                                dot = Some(c)
                            }
                            "doh3" => {
                                let c = DoH3Config::deserialize(v)
                                    .context("invalid doh3 dns listen config")?;

                                doh3 = Some(c)
                            }
                            _ => {
                                return Err(anyhow!("invalid dns listen address"));
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
        fake_ip_range: dc
            .fake_ip_range
            .parse::<ipnet::IpNet>()
            .context("invalid fake ip range")?,
        fake_ip_filter: dc.fake_ip_filter.clone(),
        store_fake_ip: def.profile.store_fake_ip,
        hosts: if dc.user_hosts && !def.hosts.is_empty() {
            Config::parse_hosts(&def.hosts).ok()
        } else {
            let mut tree = StringTrie::new();
            tree.insert(
                "localhost",
                Arc::new("127.0.0.1".parse::<IpAddr>().unwrap()),
            );
            Some(tree)
        },
        nameserver_policy,
    })
}

impl From<crate::config::def::FallbackFilter>
    for watfaq_resolver::dns::config::FallbackFilter
{
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
