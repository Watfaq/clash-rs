use std::collections::{HashMap, VecDeque};

use crate::proxy::AnyOutboundHandler;

mod healthcheck;
pub mod providers;

type Latency = VecDeque<u64>;

/// ProxyManager is only the latency registry.
/// TODO: move all proxies here, too, maybe.
pub struct ProxyManager {
    latency_map: HashMap<String, Latency>,
}

impl ProxyManager {
    pub fn new() -> Self {
        Self {
            latency_map: HashMap::new(),
        }
    }

    pub async fn check(&mut self, _proxy: &Vec<AnyOutboundHandler>) {
        todo!("check latency for proxies")
    }
}
