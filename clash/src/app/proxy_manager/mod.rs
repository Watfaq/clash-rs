use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

mod file_provider;
mod healthcheck;
mod provider;

use crate::proxy::OutboundHandler;

pub type ThreadSafeProxy = Arc<dyn OutboundHandler>;

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

    pub async fn check(&mut self, proxy: &Vec<ThreadSafeProxy>) {
        todo!("check latency for proxies")
    }
}
