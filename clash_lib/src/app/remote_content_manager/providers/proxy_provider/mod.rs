pub mod plain_provider;

pub mod proxy_set_provider;

pub use plain_provider::PlainProvider;
pub use proxy_set_provider::ProxySetProvider;

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{app::remote_content_manager::providers::Provider, proxy::AnyOutboundHandler};

pub type ThreadSafeProxyProvider = Arc<RwLock<dyn ProxyProvider + Send + Sync>>;

#[async_trait]
pub trait ProxyProvider: Provider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler>;
    async fn touch(&self);
    /// this is a blocking call, you may want to spawn a new task to run this
    async fn healthcheck(&self);
}
