use std::collections::HashMap;

use std::{fmt::Display, net::IpAddr, str::FromStr};

use ipnet::IpNet;
use serde::{de::value::MapDeserializer, Deserialize, Serialize};
use serde_yaml::Value;

use crate::{
    app::{dns, remote_content_manager::providers::rule_provider::RuleSetBehavior},
    common::auth,
    config::{
        def::{self, LogLevel, RunMode},
        internal::{
            proxy::{OutboundProxy, PROXY_DIRECT, PROXY_REJECT},
            rule::RuleType,
        },
    },
    proxy::utils::Interface,
    Error,
};

use super::proxy::{
    map_serde_error, OutboundProxyProtocol, OutboundProxyProviderDef,
};

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
}

impl Config {
    fn validate(self) -> Result<Self, crate::Error> {
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

impl TryFrom<def::Config> for Config {
    type Error = crate::Error;

    fn try_from(c: def::Config) -> Result<Self, Self::Error> {
        let mut proxy_names =
            vec![String::from(PROXY_DIRECT), String::from(PROXY_REJECT)];
        #[allow(deprecated)]
        Self {
            general: General {
                inbound: Inbound {
                    port: c.port.clone().map(|x| x.try_into()).transpose()?,
                    socks_port: c
                        .socks_port
                        .clone()
                        .map(|x| x.try_into())
                        .transpose()?,
                    redir_port: c
                        .redir_port
                        .clone()
                        .map(|x| x.try_into())
                        .transpose()?,
                    tproxy_port: c
                        .tproxy_port
                        .clone()
                        .map(|x| x.try_into())
                        .transpose()?,
                    mixed_port: c
                        .mixed_port
                        .clone()
                        .map(|x| x.try_into())
                        .transpose()?,
                    authentication: c.authentication.clone(),
                    bind_address: c.bind_address.parse()?,
                },
                controller: Controller {
                    external_controller: c.external_controller.clone(),
                    external_ui: c.external_ui.clone(),
                    secret: c.secret.clone(),
                },
                mode: c.mode,
                log_level: c.log_level,
                ipv6: c.ipv6,
                interface: c.interface.as_ref().map(|iface| {
                    if let Ok(addr) = iface.parse::<IpAddr>() {
                        Interface::IpAddr(addr)
                    } else {
                        Interface::Name(iface.to_string())
                    }
                }),
                routing_mask: c.routing_mask,
                mmdb: c.mmdb.to_owned(),
                mmdb_download_url: c.mmdb_download_url.to_owned(),
                asn_mmdb: c.asn_mmdb.to_owned(),
                asn_mmdb_download_url: c.asn_mmdb_download_url.to_owned(),
                geosite: c.geosite.to_owned(),
                geosite_download_url: c.geosite_download_url.to_owned(),
            },
            dns: (&c).try_into()?,
            experimental: c.experimental,
            tun: match c.tun {
                Some(t) => TunConfig {
                    enable: t.enable,
                    device_id: t.device_id,
                    route_all: t.route_all,
                    routes: t
                        .routes
                        .map(|r| {
                            r.into_iter()
                                .map(|x| x.parse())
                                .collect::<Result<Vec<_>, _>>()
                        })
                        .transpose()
                        .map_err(|x| {
                            Error::InvalidConfig(format!("parse tun routes: {}", x))
                        })?
                        .unwrap_or_default(),
                    gateway: t.gateway.parse().map_err(|x| {
                        Error::InvalidConfig(format!("parse tun gateway: {}", x))
                    })?,
                    mtu: t.mtu,
                    so_mark: t.so_mark,
                    route_table: t.route_table,
                    dns_hijack: match t.dns_hijack {
                        def::DnsHijack::Switch(b) => b,
                        def::DnsHijack::List(_) => true,
                    },
                },
                None => TunConfig::default(),
            },
            profile: Profile {
                store_selected: c.profile.store_selected,
            },
            rules: c
                .rule
                .into_iter()
                .map(|x| {
                    x.parse::<RuleType>()
                        .map_err(|x| Error::InvalidConfig(x.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
            rule_providers: c
                .rule_provider
                .map(|m| {
                    m.into_iter()
                            .try_fold(HashMap::new(), |mut rv, (name, mut body)| {
                                body.insert(
                                    "name".to_owned(),
                                    serde_yaml::Value::String(name.clone()),
                                );
                                let provider = RuleProviderDef::try_from(body)
                                    .map_err(|x| {
                                        Error::InvalidConfig(format!(
                                            "invalid rule provider {}: {}",
                                            name, x
                                        ))
                                    })?;
                                rv.insert(name, provider);
                                Ok::<
                                    HashMap<std::string::String, RuleProviderDef>,
                                    Error,
                                >(rv)
                            })
                            .expect("proxy provider parse error")
                })
                .unwrap_or_default(),
            users: c
                .authentication
                .into_iter()
                .map(|u| {
                    let mut parts = u.splitn(2, ':');
                    let username = parts.next().unwrap().to_string();
                    let password = parts.next().unwrap_or("").to_string();
                    auth::User::new(username, password)
                })
                .collect(),
            proxies: c.proxy.into_iter().try_fold(
                HashMap::from([
                    (
                        String::from(PROXY_DIRECT),
                        OutboundProxy::ProxyServer(OutboundProxyProtocol::Direct),
                    ),
                    (
                        String::from(PROXY_REJECT),
                        OutboundProxy::ProxyServer(OutboundProxyProtocol::Reject),
                    ),
                ]),
                |mut rv, x| {
                    let proxy = OutboundProxy::ProxyServer(
                        OutboundProxyProtocol::try_from(x)?,
                    );
                    let name = proxy.name();
                    if rv.contains_key(name.as_str()) {
                        return Err(Error::InvalidConfig(format!(
                            "duplicated proxy name: {}",
                            name,
                        )));
                    }
                    proxy_names.push(name.clone());
                    rv.insert(name, proxy);
                    Ok(rv)
                },
            )?,
            proxy_groups: c.proxy_group.into_iter().try_fold(
                HashMap::<String, OutboundProxy>::new(),
                |mut rv, mapping| {
                    let group = OutboundProxy::ProxyGroup(
                        mapping.clone().try_into().map_err(|x: Error| {
                            if let Some(name) = mapping.get("name") {
                                Error::InvalidConfig(format!(
                                    "proxy group: {}: {}",
                                    name.as_str()
                                        .expect("proxy group name must be string"),
                                    x
                                ))
                            } else {
                                Error::InvalidConfig(
                                    "proxy group name missing".to_string(),
                                )
                            }
                        })?,
                    );
                    proxy_names.push(group.name());
                    rv.insert(group.name().to_string(), group);
                    Ok::<HashMap<String, OutboundProxy>, Error>(rv)
                },
            )?,
            // https://stackoverflow.com/a/62001313/1109167
            proxy_names,
            proxy_providers: c
                .proxy_provider
                .map(|m| {
                    m.into_iter()
                        .try_fold(HashMap::new(), |mut rv, (name, mut body)| {
                            body.insert(
                                "name".to_owned(),
                                serde_yaml::Value::String(name.clone()),
                            );
                            let provider = OutboundProxyProviderDef::try_from(body)
                                .map_err(|x| {
                                    Error::InvalidConfig(format!(
                                        "invalid proxy provider {}: {}",
                                        name, x
                                    ))
                                })?;
                            rv.insert(name, provider);
                            Ok::<
                                HashMap<
                                    std::string::String,
                                    OutboundProxyProviderDef,
                                >,
                                Error,
                            >(rv)
                        })
                        .expect("proxy provider parse error")
                })
                .unwrap_or_default(),
        }
        .validate()
    }
}

#[cfg(test)]
mod tests {
    use crate::def;

    use super::Config;

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
        let cc: Config = c.try_into().expect("should into");
        assert_eq!(cc.general.inbound.port, Some(9090));
        assert_eq!(cc.general.inbound.mixed_port, Some(9091));
    }
}

pub struct General {
    pub inbound: Inbound,
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
    pub so_mark: Option<u32>,
    pub route_table: Option<u32>,
    pub dns_hijack: bool,
}

#[derive(Clone, Default)]
pub enum BindAddress {
    #[default]
    Any,
    One(Interface),
}

impl Display for BindAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindAddress::Any => write!(f, "*"),
            BindAddress::One(one) => match one {
                Interface::IpAddr(ip) => write!(f, "{}", ip),
                Interface::Name(name) => write!(f, "{}", name),
            },
        }
    }
}

impl FromStr for BindAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "*" => Ok(Self::Any),
            "localhost" => {
                Ok(Self::One(Interface::IpAddr(IpAddr::from([127, 0, 0, 1]))))
            }
            _ => {
                if let Ok(ip) = s.parse::<IpAddr>() {
                    Ok(BindAddress::One(Interface::IpAddr(ip)))
                } else {
                    Ok(BindAddress::One(Interface::Name(s.to_string())))
                }
            }
        }
    }
}

pub struct Inbound {
    pub port: Option<u16>,
    pub socks_port: Option<u16>,
    pub redir_port: Option<u16>,
    pub tproxy_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub authentication: Vec<String>,
    pub bind_address: BindAddress,
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

impl TryFrom<HashMap<String, Value>> for RuleProviderDef {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "rule provider name is required".to_owned(),
            ))?
            .to_owned();
        RuleProviderDef::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}
