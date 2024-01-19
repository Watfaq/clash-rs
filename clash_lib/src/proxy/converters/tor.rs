use crate::{
    config::internal::proxy::OutboundTor,
    proxy::{
        tor::{Handler, HandlerOptions},
        AnyOutboundHandler,
    },
};

impl TryFrom<OutboundTor> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(value: OutboundTor) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundTor> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTor) -> Result<Self, Self::Error> {
        let h = Handler::new(HandlerOptions {
            name: s.name.to_owned(),
        });
        Ok(h)
    }
}
