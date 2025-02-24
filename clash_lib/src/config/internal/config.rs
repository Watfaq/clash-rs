use std::collections::HashMap;

use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::{
    Error,
    app::{
        dns, net::Interface,
        remote_content_manager::providers::rule_provider::RuleSetBehavior,
    },
    common::auth,
    config::{
        def::{self, LogLevel, RunMode},
        internal::{proxy::OutboundProxy, rule::RuleType},
    },
};

use super::{listener::InboundOpts, proxy::OutboundProxyProviderDef};

pub struct Config {
    pub general: General,
    pub dns: dns::Config,
    pub tun: TunConfig,
    pub experimental: Option<def::Experimental>,
    pub profile: Profile,
    pub rules: Vec<RuleType>,
    pub rule_providers: HashMap<String, RuleProviderDef>,
    pub users: Vec<auth::User>,
    /// a list maintaining the order from the config file
    pub proxy_names: Vec<String>,
    pub proxies: HashMap<String, OutboundProxy>,
    pub proxy_groups: HashMap<String, OutboundProxy>,
    pub proxy_providers: HashMap<String, OutboundProxyProviderDef>,
    pub listeners: HashMap<String, InboundOpts>,
}

impl Config {
    pub fn validate(self) -> Result<Self, crate::Error> {
        for r in self.rules.iter() {
            if !self.proxies.contains_key(r.target())
                && !self.proxy_groups.contains_key(r.target())
            {
                return Err(Error::InvalidConfig(format!(
                    "proxy `{}` referenced in a rule was not found",
                    r.target()
                )));
            }
        }
        Ok(self)
    }
}

pub struct General {
    pub authentication: Vec<String>,
    pub bind_address: BindAddress,
    pub(crate) controller: Controller,
    pub mode: RunMode,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub interface: Option<Interface>,
    pub routing_mask: Option<u32>,
    pub mmdb: String,
    pub mmdb_download_url: Option<String>,
    pub asn_mmdb: String,
    pub asn_mmdb_download_url: Option<String>,

    pub geosite: String,
    pub geosite_download_url: Option<String>,
}

pub struct Profile {
    pub store_selected: bool,
    // this is read to dns config directly
    // store_fake_ip: bool,
}

#[derive(Default)]
pub struct TunConfig {
    pub enable: bool,
    pub device_id: String,
    pub route_all: bool,
    pub routes: Vec<IpNet>,
    pub gateway: IpNet,
    pub mtu: Option<u16>,
    pub so_mark: u32,
    pub route_table: u32,
    pub dns_hijack: bool,
}

#[derive(Serialize, Clone, Debug, Copy, PartialEq)]
#[serde(transparent)]
pub struct BindAddress(pub IpAddr);
impl BindAddress {
    pub fn all() -> Self {
        Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    pub fn local() -> Self {
        Self(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }
}
impl Default for BindAddress {
    fn default() -> Self {
        Self::local()
    }
}

impl<'de> Deserialize<'de> for BindAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        match str.as_str() {
            "*" => Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            "localhost" => Ok(Self(IpAddr::from([127, 0, 0, 1]))),
            _ => {
                if let Ok(ip) = str.parse::<IpAddr>() {
                    Ok(Self(ip))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "Invalid BindAddress value {str}"
                    )))
                }
            }
        }
    }
}

impl FromStr for BindAddress {
    type Err = anyhow::Error;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "*" => Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            "localhost" => Ok(Self(IpAddr::from([127, 0, 0, 1]))),
            _ => {
                if let Ok(ip) = str.parse::<IpAddr>() {
                    Ok(Self(ip))
                } else {
                    Err(anyhow!("Invalid BindAddress value {str}"))
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Controller {
    pub external_controller: Option<String>,
    pub external_ui: Option<String>,
    pub secret: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum RuleProviderDef {
    Http(HttpRuleProvider),
    File(FileRuleProvider),
}

#[derive(Serialize, Deserialize)]
pub struct HttpRuleProvider {
    pub url: String,
    pub interval: u64,
    pub behavior: RuleSetBehavior,
    pub path: String,
}

#[derive(Serialize, Deserialize)]
pub struct FileRuleProvider {
    pub path: String,
    pub interval: Option<u64>,
    pub behavior: RuleSetBehavior,
}

#[cfg(test)]
mod tests {
    use crate::config::{def, internal::convert::convert, listener::InboundOpts};
    #[test]
    fn from_def_config() {
        let cfg = r#"
        port: 9090
        mixed-port: "9091"
        "#;
        let c = cfg.parse::<def::Config>().expect("should parse");
        assert_eq!(c.port.clone().map(|x| x.try_into().unwrap()), Some(9090));
        assert_eq!(
            c.mixed_port.clone().map(|x| x.try_into().unwrap()),
            Some(9091)
        );
        let cc = convert(c).expect("should convert");

        assert!(
            cc.listeners
                .iter()
                .find(|(_, listener)| match listener {
                    InboundOpts::Http { common_opts, .. } =>
                        common_opts.port == 9090,
                    _ => false,
                })
                .is_some()
        );
        assert!(
            cc.listeners
                .iter()
                .find(|(_, listener)| match listener {
                    InboundOpts::Mixed { common_opts, .. } =>
                        common_opts.port == 9091,
                    _ => false,
                })
                .is_some()
        );
    }
}
