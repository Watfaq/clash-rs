use crate::{
    config::internal::proxy::OutboundGroupRelay,
    proxy::{
        relay::{Handler, HandlerOptions},
        AnyOutboundHandler, CommonOption,
    },
};

impl TryFrom<OutboundGroupRelay> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(value: OutboundGroupRelay) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundGroupRelay> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(value: &OutboundGroupRelay) -> Result<Self, Self::Error> {
        Ok(Handler::new(
            HandlerOptions {
                name: value.name.to_owned(),
                common_opts: CommonOption::default(),
            },
            vec![],
        ))
    }
}
