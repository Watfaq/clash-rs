use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::proxy::AnyOutboundHandler;

use super::Provider;

pub type ThreadSafeProxyProvider = Arc<Mutex<dyn ProxyProvider + Send + Sync>>;

#[async_trait]
pub trait ProxyProvider: Provider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler>;
    async fn touch(&self);
    async fn healthcheck(&self);
}
