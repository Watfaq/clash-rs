use ipnet::IpNet;

use crate::{
    config::internal::proxy::OutboundWireguard,
    proxy::{
        wg::{Handler, HandlerOptions},
        AnyOutboundHandler, CommonOption,
    },
    Error,
};

impl TryFrom<OutboundWireguard> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundWireguard) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundWireguard> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundWireguard) -> Result<Self, Self::Error> {
        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: CommonOption {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            ip: s
                .ip
                .parse::<IpNet>()
                .map(|x| match x.addr() {
                    std::net::IpAddr::V4(v4) => Ok(v4),
                    std::net::IpAddr::V6(_) => Err(Error::InvalidConfig(
                        "invalid ip address: put an v4 address here".to_owned(),
                    )),
                })
                .map_err(|x| {
                    Error::InvalidConfig(format!(
                        "invalid ip address: {}, {}",
                        x, s.ip
                    ))
                })??,
            ipv6: s
                .ipv6
                .as_ref()
                .and_then(|x| {
                    x.parse::<IpNet>()
                        .map(|x| match x.addr() {
                            std::net::IpAddr::V4(_) => Err(Error::InvalidConfig(
                                "invalid ip address: put an v6 address here"
                                    .to_owned(),
                            )),
                            std::net::IpAddr::V6(v6) => Ok(v6),
                        })
                        .map_err(|e| {
                            Error::InvalidConfig(format!(
                                "invalid ipv6 address: {}, {}",
                                e, x
                            ))
                        })
                        .ok()
                })
                .transpose()?,
            private_key: s.private_key.to_owned(),
            public_key: s.public_key.to_owned(),
            preshared_key: s.preshared_key.as_ref().map(|x| x.to_owned()),
            remote_dns_resolve: s.remote_dns_resolve.unwrap_or_default(),
            dns: s.dns.as_ref().map(|x| x.to_owned()),
            mtu: s.mtu,
            udp: s.udp.unwrap_or_default(),
            allowed_ips: s.allowed_ips.as_ref().map(|x| x.to_owned()),
            reserved_bits: s.reserved_bits.as_ref().map(|x| x.to_owned()),
        });
        Ok(h)
    }
}
