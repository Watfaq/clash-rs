use crate::{
    config::{config, def},
    Error,
};

pub fn convert(
    before: Option<def::TunConfig>,
) -> Result<config::TunConfig, crate::Error> {
    match before {
        Some(t) => Ok(config::TunConfig {
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
        }),
        None => Ok(config::TunConfig::default()),
    }
}
