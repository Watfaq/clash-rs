use std::collections::HashMap;
use std::fmt::format;
use std::net::SocketAddr;

use crate::config::def;
use crate::config::internal::proxy::{
    OutboundGroupProtocol, OutboundProxy, PROXY_DIRECT, PROXY_REJECT,
};
use crate::config::internal::rule::Rule;
use crate::{
    app::dns,
    config::def::{Experimental, LogLevel, RunMode},
    Error,
};

use super::proxy::OutboundProxyProtocol;

pub struct Config {
    general: General,
    dns: dns::Config,
    experimental: Option<Experimental>,
    profile: Profile,
    rules: Vec<Rule>,
    /// a list maintaining the order from the config file
    proxy_names: Vec<String>,
    proxies: HashMap<String, OutboundProxy>,
    proxy_groups: HashMap<String, OutboundProxy>,
}

impl TryFrom<def::Config> for Config {
    type Error = crate::Error;

    fn try_from(c: crate::Config) -> Result<Self, Self::Error> {
        let mut proxy_names = vec![String::from(PROXY_DIRECT), String::from(PROXY_REJECT)];
        Ok(Self {
            general: General {
                inbound: Inbound {
                    port: c.port,
                    socks_port: c.socks_port,
                    redir_port: c.redir_port,
                    tproxy_port: c.tproxy_port,
                    mixed_port: c.mixed_port,
                    authentication: c.authentication,
                    bind_address: match c.bind_address {
                        a if a == "*" => BindAddress::Any,
                        a => a.parse()?,
                    },
                },
                controller: Controller {
                    external_controller: c.external_controller,
                    external_ui: c.external_ui,
                    secret: c.secret,
                },
                mode: c.mode,
                log_level: c.log_level,
                ipv6: c.ipv6.unwrap_or(false),
                interface: c.interface.map(|iface| {
                    if let Some(addr) = iface.parse::<SocketAddr>() {
                        BindInterface::Addr(addr)
                    } else {
                        BindInterface::Name(iface)
                    }
                }),
                routing_mask: c.routing_mask,
            },
            dns: c.dns.try_into()?,
            experimental: c.experimental,
            profile: Profile {
                store_selected: c.profile.store_selected,
                store_fakeip: c.profile.store_fake_ip,
            },
            rules: c.rule.into_iter().map(|x| x.parse::<Rule>()?).collect(),
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
                    if rv.contains_key(name) {
                        return Err(Error::InvalidConfig(format!(
                            "duplicated proxy name: {}",
                            name,
                        )));
                    }
                    proxy_names.push(name.into());
                    rv.insert(String::from(name), proxy);
                    Ok(rv)
                },
            )?,
            proxy_groups: c.proxy_group.into_iter().try_fold(
                HashMap::new(),
                |mut rv, mapping| {
                    let group =
                        OutboundProxy::ProxyGroup(OutboundGroupProtocol::try_from(mapping)?);
                    proxy_names.push(group.name().into());
                    rv.insert(group.name().to_string(), group);
                    Ok(rv)
                },
            )?,
            // https://stackoverflow.com/a/62001313/1109167
            proxy_names,
        })
    }
}

pub enum BindInterface {
    Name(String),
    Addr(SocketAddr),
}

pub struct General {
    inbound: Inbound,
    controller: Controller,
    mode: RunMode,
    log_level: LogLevel,
    ipv6: bool,
    interface: Option<BindInterface>,
    routing_mask: Option<u32>,
}

struct Profile {
    store_selected: bool,
    store_fakeip: bool,
}

pub enum BindAddress {
    Any,
    One(SocketAddr),
}

pub struct Inbound {
    pub port: Option<i16>,
    pub socks_port: Option<i16>,
    pub redir_port: Option<i16>,
    pub tproxy_port: Option<i16>,
    pub mixed_port: Option<i16>,
    pub authentication: Vec<String>,
    pub bind_address: BindAddress,
}

struct Controller {
    external_controller: Option<String>,
    external_ui: Option<String>,
    secret: Option<String>,
}
