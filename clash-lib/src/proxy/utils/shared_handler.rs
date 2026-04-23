use std::{collections::HashMap, fmt, io, sync::Arc};

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::warn;

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

pub type OutboundHandlerRegistry = Arc<RwLock<HashMap<String, AnyOutboundHandler>>>;

/// A globally-shared DIRECT handler used as the fallback when a named proxy
/// cannot be found in the registry.  Avoids allocating a new `Handler` on
/// every lookup miss.
pub(crate) static FALLBACK_DIRECT: std::sync::LazyLock<AnyOutboundHandler> =
    std::sync::LazyLock::new(|| {
        Arc::new(direct::Handler::new(PROXY_DIRECT)) as AnyOutboundHandler
    });

/// An outbound handler that dynamically resolves to an actual handler
/// from a shared registry at connection time. This allows DNS and HTTP
/// clients to reference proxy groups and providers that are initialized
/// after the DNS resolver itself.
pub struct SharedOutboundHandler {
    name: String,
    registry: OutboundHandlerRegistry,
}

/// Construct an `OutboundHandlerRegistry` that contains only the built-in
/// DIRECT handler.  Useful for contexts (e.g. DHCP DNS probing) that always
/// connect directly and should not trigger registry-miss warnings.
pub fn direct_only_registry() -> OutboundHandlerRegistry {
    let mut map = HashMap::new();
    map.insert(PROXY_DIRECT.to_owned(), FALLBACK_DIRECT.clone());
    Arc::new(RwLock::new(map))
}

impl SharedOutboundHandler {
    pub fn new(name: String, registry: OutboundHandlerRegistry) -> Self {
        Self { name, registry }
    }

    async fn get_inner(&self) -> AnyOutboundHandler {
        match self.registry.read().await.get(&self.name).cloned() {
            Some(h) => h,
            None => {
                // Only warn when the proxy name is not the well-known DIRECT
                // constant.  DIRECT is never inserted into the registry
                // explicitly, so a miss is expected and silent.
                if self.name != PROXY_DIRECT {
                    warn!(
                        proxy = %self.name,
                        "proxy not found in registry, falling back to DIRECT"
                    );
                }
                FALLBACK_DIRECT.clone()
            }
        }
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
        // proto() is a synchronous trait method so we cannot resolve the inner
        // handler here. The trait documentation states this value is informational
        // only ("do not rely on the underlying value"), so Direct is a safe
        // placeholder.
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
