use crate::{
    config::internal::proxy::OutboundTuic,
    proxy::{
        tuic::{Handler, HandlerOptions},
        AnyOutboundHandler,
    },
};

impl TryFrom<OutboundTuic> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(value: OutboundTuic) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundTuic> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTuic) -> Result<Self, Self::Error> {
        Handler::new(HandlerOptions {
            name: s.name.to_owned(),
            server: s.server.to_owned(),
            port: s.port,
            uuid: s.uuid.to_owned(),
            password: s.password.to_owned(),
            udp_relay_mode: s.udp_relay_mode.to_owned().unwrap_or("native".to_string()),
            disable_sni: false,
        })
        .map_err(|e| {
            // TODO find a better way
            crate::Error::Operation(e.to_string())
        })
    }
}
