use std::collections::HashMap;

use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::config::def;
use crate::config::internal::proxy::{OutboundProxy, PROXY_DIRECT, PROXY_REJECT};
use crate::config::internal::rule::RuleType;
use crate::proxy::utils::Interface;
use crate::{
    app::dns,
    config::def::{Experimental, LogLevel, RunMode},
    Error,
};

use super::proxy::{OutboundProxyProtocol, OutboundProxyProvider};

pub struct Config {
    pub general: General,
    pub dns: dns::Config,
    pub experimental: Option<Experimental>,
    pub profile: Profile,
    pub rules: Vec<RuleType>,
    /// a list maintaining the order from the config file
    proxy_names: Vec<String>,
    pub proxies: HashMap<String, OutboundProxy>,
    pub proxy_groups: HashMap<String, OutboundProxy>,
    pub proxy_providers: HashMap<String, OutboundProxyProvider>,
}

impl Config {
    pub fn validate(&self) -> Result<(), crate::Error> {
        //TODO: validate proxy group loop
        Ok(())
    }
}

impl TryFrom<def::Config> for Config {
    type Error = crate::Error;

    fn try_from(c: def::Config) -> Result<Self, Self::Error> {
        let mut proxy_names = vec![String::from(PROXY_DIRECT), String::from(PROXY_REJECT)];
        Ok(Self {
            general: General {
                inbound: Inbound {
                    port: c.port,
                    socks_port: c.socks_port,
                    redir_port: c.redir_port,
                    tproxy_port: c.tproxy_port,
                    mixed_port: c.mixed_port,
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
                ipv6: c.ipv6.unwrap_or(false),
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
            },
            dns: (&c).try_into()?,
            experimental: c.experimental,
            profile: Profile {
                store_selected: c.profile.store_selected,
                store_fakeip: c.profile.store_fake_ip,
            },
            rules: c
                .rule
                .into_iter()
                .map(|x| {
                    x.parse::<RuleType>()
                        .map_err(|x| Error::InvalidConfig(x.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,

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
                    let proxy = OutboundProxy::ProxyServer(OutboundProxyProtocol::try_from(x)?);
                    let name = proxy.name();
                    if rv.contains_key(name.as_str()) {
                        return Err(Error::InvalidConfig(format!(
                            "duplicated proxy name: {}",
                            name,
                        )));
                    }
                    proxy_names.push(name.clone());
                    rv.insert(String::from(name), proxy);
                    Ok(rv)
                },
            )?,
            proxy_groups: c.proxy_group.into_iter().try_fold(
                HashMap::<String, OutboundProxy>::new(),
                |mut rv, mapping| {
                    let group = OutboundProxy::ProxyGroup(mapping.clone().try_into().map_err(
                        |x: Error| {
                            if let Some(name) = mapping.get("name") {
                                Error::InvalidConfig(format!(
                                    "proxy group: {}: {}",
                                    name.as_str().expect("proxy group name must be string"),
                                    x.to_string()
                                ))
                            } else {
                                Error::InvalidConfig("proxy group name missing".to_string())
                            }
                        },
                    )?);
                    proxy_names.push(group.name().into());
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
                        .try_fold(HashMap::new(), |mut rv, (name, body)| {
                            let provider = OutboundProxyProvider::try_from(body).map_err(|x| {
                                Error::InvalidConfig(format!(
                                    "invalid proxy provider {}: {}",
                                    name, x
                                ))
                            })?;
                            rv.insert(name, provider);
                            Ok::<HashMap<std::string::String, OutboundProxyProvider>, Error>(rv)
                        })
                        .expect("proxy provider parse error")
                })
                .unwrap_or_default(),
        })
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
        "#;
        let c = cfg.parse::<def::Config>().expect("should parse");
        assert_eq!(c.port, Some(9090));
        let cc: Config = c.try_into().expect("should into");
        assert_eq!(cc.general.inbound.port, Some(9090));
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct General {
    pub(crate) inbound: Inbound,
    #[serde(skip)]
    pub(crate) controller: Controller,
    pub mode: RunMode,
    pub log_level: LogLevel,
    pub ipv6: bool,
    #[serde(skip)]
    pub interface: Option<Interface>,
    #[serde(skip)]
    pub routing_mask: Option<u32>,
    #[serde(skip)]
    pub mmdb: String,
    #[serde(skip)]
    pub mmdb_download_url: Option<String>,
}

pub struct Profile {
    store_selected: bool,
    store_fakeip: bool,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub enum BindAddress {
    #[default]
    #[serde(rename = "*")]
    Any,
    One(Interface),
}

impl FromStr for BindAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "*" => Ok(Self::Any),
            "localhost" => Ok(Self::One(Interface::IpAddr(IpAddr::from([127, 0, 0, 1])))),
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

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Inbound {
    pub port: Option<u16>,
    pub socks_port: Option<u16>,
    pub redir_port: Option<u16>,
    pub tproxy_port: Option<u16>,
    pub mixed_port: Option<u16>,
    #[serde(skip)]
    pub authentication: Vec<String>,
    pub bind_address: BindAddress,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Controller {
    pub external_controller: Option<String>,
    pub external_ui: Option<String>,
    pub secret: Option<String>,
}
