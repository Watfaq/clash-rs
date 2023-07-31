use std::collections::{HashMap, VecDeque};

use crate::proxy::AnyOutboundHandler;

use self::providers::proxy_provider::ThreadSafeProxyProvider;

pub mod healthcheck;
pub mod providers;

type Latency = VecDeque<u64>;

/// ProxyManager is only the latency registry.
/// TODO: move all proxies here, too, maybe.
#[derive(Default)]
pub struct ProxyManager {
    latency_map: HashMap<String, Latency>,
    proxy_provider: HashMap<String, ThreadSafeProxyProvider>,
}

impl ProxyManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn check(&mut self, _proxy: &Vec<AnyOutboundHandler>) {
        todo!("check latency for proxies")
    }
}
