use serde::{Deserialize, de::value::MapDeserializer};
use serde_yaml::Value;
use std::collections::{HashMap, HashSet};
use tracing::warn;

use crate::{
    Error,
    config::{
        config::BindAddress,
        def::{self, Port},
        listener::{CommonInboundOpts, InboundOpts},
        proxy::map_serde_error,
    },
};

/// combines the top-level config and config.listeners to a set of inbound
/// options.
pub(super) fn convert(
    raw: Option<Vec<HashMap<String, Value>>>,
    c: &def::Config,
) -> Result<HashSet<InboundOpts>, crate::Error> {
    let http_port = c.port;
    let socks_port = c.socks_port;
    let mixed_port = c.mixed_port;
    #[cfg(feature = "tproxy")]
    let tproxy_port = c.tproxy_port;
    #[cfg(feature = "redir")]
    let redir_port = c.redir_port;
    let bind_address = if c.bind_address == BindAddress::default() && c.ipv6 {
        BindAddress::dual_stack()
    } else {
        c.bind_address
    };

    let inbounds = raw
        .unwrap_or_default()
        .into_iter()
        .map(InboundOpts::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let mut all_inbounds = HashSet::new();
    for inbound in inbounds {
        if all_inbounds.contains(&inbound) {
            warn!("Duplicate inbound listener found: {:?}", inbound);
            continue;
        }
        all_inbounds.insert(inbound);
    }

    // Add short-handed top-level proxies to inbounds
    if let Some(Port(http_port)) = http_port
        && !all_inbounds.insert(InboundOpts::Http {
            common_opts: CommonInboundOpts {
                name: "HTTP-IN".into(),
                listen: bind_address,
                port: http_port,
                allow_lan: c.allow_lan.unwrap_or_default(),
                fw_mark: c.routing_mark,
            },
        })
    {
        warn!("Duplicate HTTP inbound listener found: {}", http_port);
    }
    if let Some(Port(socks_port)) = socks_port
        && !all_inbounds.insert(InboundOpts::Socks {
            common_opts: CommonInboundOpts {
                name: "SOCKS-IN".into(),
                listen: bind_address,
                port: socks_port,
                allow_lan: c.allow_lan.unwrap_or_default(),
                fw_mark: c.routing_mark,
            },
            udp: true,
        })
    {
        warn!("Duplicate SOCKS inbound listener found: {}", socks_port);
    }
    if let Some(Port(mixed_port)) = mixed_port
        && !all_inbounds.insert(InboundOpts::Mixed {
            common_opts: CommonInboundOpts {
                name: "MIXED-IN".into(),
                listen: bind_address,
                port: mixed_port,
                allow_lan: c.allow_lan.unwrap_or_default(),
                fw_mark: c.routing_mark,
            },
            udp: true,
        })
    {
        warn!("Duplicate MIXED inbound listener found: {}", mixed_port);
    }
    #[cfg(feature = "redir")]
    if let Some(Port(redir_port)) = redir_port
        && !all_inbounds.insert(InboundOpts::Redir {
            common_opts: CommonInboundOpts {
                name: "REDIR-IN".into(),
                listen: bind_address,
                port: redir_port,
                allow_lan: c.allow_lan.unwrap_or_default(),
                fw_mark: c.routing_mark,
            },
        })
    {
        warn!("Duplicate REDIR inbound listener found: {}", redir_port);
    }
    #[cfg(feature = "tproxy")]
    if let Some(Port(tproxy_port)) = tproxy_port
        && !all_inbounds.insert(InboundOpts::TProxy {
            common_opts: CommonInboundOpts {
                name: "TPROXY-IN".into(),
                listen: bind_address,
                port: tproxy_port,
                allow_lan: c.allow_lan.unwrap_or_default(),
                fw_mark: c.routing_mark,
            },
            udp: true,
        })
    {
        warn!("Duplicate TPROXY inbound listener found: {}", tproxy_port);
    }
    Ok(all_inbounds)
}

impl TryFrom<HashMap<String, Value>> for InboundOpts {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .and_then(|v| if v.is_empty() { None } else { Some(v) })
            .ok_or(Error::InvalidConfig(
                "missing field `name` in inbound listener".to_owned(),
            ))?
            .to_owned();
        InboundOpts::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}
