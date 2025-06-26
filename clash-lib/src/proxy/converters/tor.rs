use crate::{
    config::internal::proxy::OutboundTor,
    proxy::tor::{Handler, HandlerOptions},
};

impl TryFrom<OutboundTor> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTor) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundTor> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTor) -> Result<Self, Self::Error> {
        let h = Handler::new(HandlerOptions {
            name: s.name.to_owned(),
        });
        Ok(h)
    }
}
