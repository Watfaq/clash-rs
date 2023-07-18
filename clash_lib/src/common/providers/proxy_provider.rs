use std::sync::Arc;

use crate::config::internal::proxy::OutboundProxy;

pub type ThreadSafeProxyProvider = Arc<dyn ProxyProvider + Send + Sync>;

pub trait ProxyProvider {
    fn proxies(&self) -> Vec<OutboundProxy>;
    fn touch(&self);
    fn healthcheck(&self);
}
