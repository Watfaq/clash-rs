use std::{collections::HashMap, fmt, io, sync::Arc};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
    },
    config::internal::proxy::PROXY_DIRECT,
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, OutboundHandler,
        OutboundType, direct,
    },
    session::Session,
};

pub type OutboundHandlerRegistry =
    Arc<RwLock<HashMap<String, AnyOutboundHandler>>>;

/// An outbound handler that dynamically resolves to an actual handler
/// from a shared registry at connection time. This allows DNS and HTTP
/// clients to reference proxy groups and providers that are initialized
/// after the DNS resolver itself.
pub struct SharedOutboundHandler {
    name: String,
    registry: OutboundHandlerRegistry,
}

impl SharedOutboundHandler {
    pub fn new(name: String, registry: OutboundHandlerRegistry) -> Self {
        Self { name, registry }
    }

    async fn get_inner(&self) -> AnyOutboundHandler {
        self.registry
            .read()
            .await
            .get(&self.name)
            .cloned()
            .unwrap_or_else(|| {
                Arc::new(direct::Handler::new(PROXY_DIRECT)) as AnyOutboundHandler
            })
    }
}

impl fmt::Debug for SharedOutboundHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedOutboundHandler({})", self.name)
    }
}

#[async_trait]
impl DialWithConnector for SharedOutboundHandler {}

#[async_trait]
impl OutboundHandler for SharedOutboundHandler {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Direct
    }

    async fn support_udp(&self) -> bool {
        self.get_inner().await.support_udp().await
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        self.get_inner().await.connect_stream(sess, resolver).await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        self.get_inner()
            .await
            .connect_datagram(sess, resolver)
            .await
    }

    async fn support_connector(&self) -> ConnectorType {
        self.get_inner().await.support_connector().await
    }
}
