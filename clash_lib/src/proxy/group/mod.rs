use crate::proxy::{AnyOutboundHandler, OutboundHandler};
use async_trait::async_trait;
use erased_serde::Serialize;
use std::collections::HashMap;

pub mod fallback;
pub mod loadbalance;
pub mod relay;
pub mod selector;
pub mod smart;
pub mod urltest;

/// Convenience trait for group proxy serializing API responses.
#[async_trait]
pub trait GroupProxyAPIResponse: OutboundHandler {
    /// Returns all proxies in the group, which are usually stored in a list of
    /// ProxyProviders.
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler>;
    /// Returns the current effective proxy for the group.
    /// e.g. for a selector, it returns the currently selected proxy, and for
    /// urltest, it returns the fastest proxy, etc.
    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler>;

    /// Returns the latency test URL for the group.
    fn get_latency_test_url(&self) -> Option<String>;

    /// used in the API responses.
    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = self.get_proxies().await;

        let mut m = HashMap::new();
        m.insert("type".to_string(), Box::new(self.proto()) as _);

        if let Some(active) = self.get_active_proxy().await {
            m.insert("now".to_string(), Box::new(active.name().to_owned()) as _);
        }

        let icon = self.icon();
        if let Some(icon) = icon {
            m.insert("icon".to_string(), Box::new(icon) as _);
        }

        m.insert(
            "all".to_string(),
            Box::new(all.iter().map(|x| x.name().to_owned()).collect::<Vec<_>>())
                as _,
        );
        m
    }

    fn icon(&self) -> Option<String> {
        None
    }
}
