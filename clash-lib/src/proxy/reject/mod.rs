use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
    },
    config::internal::proxy::PROXY_REJECT,
    proxy::OutboundHandler,
    session::Session,
};
use async_trait::async_trait;
use serde::Serialize;
use std::io;

use super::{ConnectorType, DialWithConnector, OutboundType};

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

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
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
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }

    async fn connect_datagram(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }
}
