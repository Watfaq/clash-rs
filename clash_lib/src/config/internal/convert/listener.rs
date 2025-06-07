use std::collections::HashMap;

use serde::{Deserialize as _, de::value::MapDeserializer};
use serde_yaml::Value;
use tracing::warn;

use crate::{
    Error,
    config::{
        def::{self, Port},
        listener::{CommonInboundOpts, InboundOpts},
        proxy::map_serde_error,
    },
};

pub(super) fn convert(
    raw: Option<Vec<HashMap<String, Value>>>,
    c: &def::Config,
) -> Result<HashMap<String, InboundOpts>, crate::Error> {
    let http_port = c.port;
    let socks_port = c.socks_port;
    let mixed_port = c.mixed_port;
    let tpoxy_port = c.tproxy_port;
    let redir_port = c.redir_port;
    let bind_address = c.bind_address;
    let mut inbounds = raw.unwrap_or_default().into_iter().try_fold(
        HashMap::with_capacity(3),
        |mut accum, raw| {
            let inbound = InboundOpts::try_from(raw)?;
            let mut duplicate = false;
            match &inbound {
                InboundOpts::Http { common_opts, .. } => {
                    if let Some(Port(port)) = http_port {
                        if port == common_opts.port
                            && c.bind_address == common_opts.listen
                        {
                            duplicate = true;
                        }
                    }
                }
                InboundOpts::Socks { common_opts, .. } => {
                    if let Some(Port(port)) = socks_port {
                        if port == common_opts.port
                            && c.bind_address == common_opts.listen
                        {
                            duplicate = true;
                        }
                    }
                }
                InboundOpts::Mixed { common_opts, .. } => {
                    if let Some(Port(port)) = mixed_port {
                        if port == common_opts.port
                            && c.bind_address == common_opts.listen
                        {
                            duplicate = true;
                        }
                    }
                }
                InboundOpts::TProxy { common_opts, .. } => {
                    if let Some(Port(port)) = mixed_port {
                        if port == common_opts.port
                            && c.bind_address == common_opts.listen
                        {
                            duplicate = true;
                        }
                    }
                }
                InboundOpts::Redir { common_opts, .. } => {
                    if let Some(Port(port)) = mixed_port {
                        if port == common_opts.port
                            && c.bind_address == common_opts.listen
                        {
                            duplicate = true;
                        }
                    }
                }
                _ => {}
            }
            if !duplicate {
                accum.insert(inbound.common_opts().name.clone(), inbound);
            } else {
                // TODO improve log, more info
                warn!("duplicate inbound detected");
            }
            Ok::<HashMap<String, InboundOpts>, Error>(accum)
        },
    )?;
    // Add short-handed top-level proxies to inbounds
    if let Some(Port(http_port)) = http_port {
        inbounds.insert(
            "HTTP-IN".into(),
            InboundOpts::Http {
                common_opts: CommonInboundOpts {
                    name: "HTTP-IN".into(),
                    listen: bind_address,
                    port: http_port,
                    allow_lan: c.allow_lan.unwrap_or_default(),
                    fw_mark: c.routing_mask,
                },
                inherited: true,
            },
        );
    }
    if let Some(Port(socks_port)) = socks_port {
        inbounds.insert(
            "SOCKS-IN".into(),
            InboundOpts::Socks {
                common_opts: CommonInboundOpts {
                    name: "SOCKS-IN".into(),
                    listen: bind_address,
                    port: socks_port,
                    allow_lan: c.allow_lan.unwrap_or_default(),
                    fw_mark: c.routing_mask,
                },
                udp: true,
                inherited: true,
            },
        );
    }
    if let Some(Port(mixed_port)) = mixed_port {
        inbounds.insert(
            "MIXED-IN".into(),
            InboundOpts::Mixed {
                common_opts: CommonInboundOpts {
                    name: "MIXED-IN".into(),
                    listen: bind_address,
                    port: mixed_port,
                    allow_lan: c.allow_lan.unwrap_or_default(),
                    fw_mark: c.routing_mask,
                },
                udp: true,
                inherited: true,
            },
        );
    }
    if let Some(Port(redir_port)) = redir_port {
        inbounds.insert(
            "REDIR-IN".into(),
            InboundOpts::Redir {
                common_opts: CommonInboundOpts {
                    name: "REDIR-IN".into(),
                    listen: bind_address,
                    port: redir_port,
                    allow_lan: c.allow_lan.unwrap_or_default(),
                    fw_mark: c.routing_mask,
                },
                inherited: true,
            },
        );
    }
    if let Some(Port(tproxy_port)) = tpoxy_port {
        inbounds.insert(
            "TPROXY-IN".into(),
            InboundOpts::TProxy {
                common_opts: CommonInboundOpts {
                    name: "TPROXY-IN".into(),
                    listen: bind_address,
                    port: tproxy_port,
                    allow_lan: c.allow_lan.unwrap_or_default(),
                    fw_mark: c.routing_mask,
                },
                udp: true,
                inherited: true,
            },
        );
    }
    Ok(inbounds)
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
