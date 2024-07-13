use crate::{
    config::internal::proxy::OutboundSocks5,
    proxy::{
        socks::{Handler, HandlerOptions},
        AnyOutboundHandler,
    },
};

impl TryFrom<OutboundSocks5> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(value: OutboundSocks5) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundSocks5> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(s: &OutboundSocks5) -> Result<Self, Self::Error> {
        let h = Handler::new(HandlerOptions {
            name: s.name.to_owned(),
            common_opts: Default::default(),
            server: s.server.to_owned(),
            port: s.port,
            user: s.username.clone(),
            password: s.password.clone(),
            udp: s.udp,
            tls: s.tls,
            sni: s.sni.clone().unwrap_or(s.server.to_owned()),
            skip_cert_verify: s.skip_cert_verify,
        });
        Ok(h)
    }
}
