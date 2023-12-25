use crate::{
    config::internal::proxy::OutboundWireguard,
    proxy::{
        wg::{Handler, HandlerOpts},
        AnyOutboundHandler,
    },
    Error,
};

impl TryFrom<OutboundWireguard> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(value: OutboundWireguard) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundWireguard> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(s: &OutboundWireguard) -> Result<Self, Self::Error> {
        let h = Handler::new(HandlerOpts {
            name: s.name.to_owned(),
            common_opts: Default::default(),
            server: s.server.to_owned(),
            port: s.port,
            ip: s
                .ip
                .parse()
                .map_err(|x| Error::InvalidConfig(format!("invalid ip address: {}", x)))?,
            ipv6: s
                .ipv6
                .as_ref()
                .map(|x| {
                    x.parse()
                        .map_err(|x| Error::InvalidConfig(format!("invalid ipv6 address: {}", x)))
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
        });
        Ok(h)
    }
}
