use futures::StreamExt;
use std::collections::HashMap;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tower::ServiceExt;

use crate::config::def;
use crate::config::internal::proxy::{OutboundProxy, PROXY_DIRECT, PROXY_REJECT};
use crate::config::internal::rule::Rule;
use crate::{
    app::dns,
    config::def::{Experimental, LogLevel, RunMode},
    Error,
};

use super::proxy::OutboundProxyProtocol;

pub struct Config {
    pub general: General,
    pub dns: dns::Config,
    pub experimental: Option<Experimental>,
    pub profile: Profile,
    pub rules: Vec<Rule>,
    /// a list maintaining the order from the config file
    proxy_names: Vec<String>,
    pub proxies: HashMap<String, OutboundProxy>,
    pub proxy_groups: HashMap<String, OutboundProxy>,
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
                    if let Ok(addr) = iface.parse::<SocketAddr>() {
                        BindInterface::Addr(addr)
                    } else {
                        BindInterface::Name(iface.to_string())
                    }
                }),
                routing_mask: c.routing_mask,
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
                    x.parse::<Rule>()
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
                    let group = OutboundProxy::ProxyGroup(mapping.try_into()?);
                    proxy_names.push(group.name().into());
                    rv.insert(group.name().to_string(), group);
                    Ok::<HashMap<String, OutboundProxy>, Error>(rv)
                },
            )?,
            // https://stackoverflow.com/a/62001313/1109167
            proxy_names,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::def;
    use serde_yaml::Value;

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

pub enum BindInterface {
    Name(String),
    Addr(SocketAddr),
}

pub struct General {
    pub(crate) inbound: Inbound,
    controller: Controller,
    mode: RunMode,
    pub log_level: LogLevel,
    ipv6: bool,
    interface: Option<BindInterface>,
    routing_mask: Option<u32>,
}

pub struct Profile {
    store_selected: bool,
    store_fakeip: bool,
}

#[derive(Clone)]
pub enum BindAddress {
    Any,
    One(IpAddr),
}

impl FromStr for BindAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "*" => Ok(Self::Any),
            _ => Ok(Self::One(s.parse::<IpAddr>().map_err(|x| {
                Error::InvalidConfig(format!("invalid bind-address: {}, {}", s, x.to_string()))
            })?)),
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

struct Controller {
    external_controller: Option<String>,
    external_ui: Option<String>,
    secret: Option<String>,
}
