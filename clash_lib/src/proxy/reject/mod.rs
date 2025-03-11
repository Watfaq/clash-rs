use crate::{
    app::dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
    config::internal::proxy::PROXY_REJECT,
    proxy::AbstractOutboundHandler,
    session::Session,
};
use async_trait::async_trait;
use serde::Serialize;
use std::io;
use watfaq_error::Result;

use super::{ConnectorType, OutboundType};

#[derive(Serialize)]
pub struct Handler;

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reject").finish()
    }
}

impl Handler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AbstractOutboundHandler for Handler {
    fn name(&self) -> &str {
        PROXY_REJECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Reject
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        #[allow(unused_variables)] sess: &Session,
    ) -> Result<BoxedChainedStream> {
        Err(anyhow!("REJECT"))
    }

    async fn connect_datagram(
        &self,
        #[allow(unused_variables)] sess: &Session,
    ) -> Result<BoxedChainedDatagram> {
        Err(anyhow!("REJECT"))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }
}
