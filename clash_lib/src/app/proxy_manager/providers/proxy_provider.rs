use std::sync::Arc;

use async_trait::async_trait;

use crate::app::proxy_manager::ThreadSafeProxy;

use super::Provider;

pub type ThreadSafeProxyProvider = Arc<dyn ProxyProvider + Send + Sync>;

#[async_trait]
pub trait ProxyProvider: Provider {
    async fn proxies(&self) -> Vec<ThreadSafeProxy>;
    async fn touch(&mut self);
    async fn healthcheck(&self);
}
