use std::{collections::VecDeque, ops::Range, sync::Arc};

use anyhow::ContextCompat;
use rand::{seq::SliceRandom, thread_rng};

const MIN_PORT: u16 = 1025;
const MAX_PORT: u16 = 60000;
const PORT_RANGE: Range<u16> = MIN_PORT..MAX_PORT;

/// A pool of virtual ports available for TCP connections.
#[derive(Clone)]
pub struct PortPool {
    inner: Arc<tokio::sync::RwLock<TcpPortPoolInner>>,
}

impl Default for PortPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PortPool {
    /// Initializes a new pool of virtual ports.
    pub fn new() -> Self {
        let mut inner = TcpPortPoolInner::default();
        let mut ports: Vec<u16> = PORT_RANGE.collect();
        ports.shuffle(&mut thread_rng());
        ports
            .into_iter()
            .for_each(|p| inner.queue.push_back(p) as ());
        Self {
            inner: Arc::new(tokio::sync::RwLock::new(inner)),
        }
    }

    /// Requests a free port from the pool. An error is returned if none is available (exhausted max capacity).
    pub async fn next(&self) -> anyhow::Result<u16> {
        let mut inner = self.inner.write().await;
        let port = inner
            .queue
            .pop_front()
            .with_context(|| "virtual port pool is exhausted")?;
        Ok(port)
    }

    /// Releases a port back into the pool.
    pub async fn release(&self, port: u16) {
        let mut inner = self.inner.write().await;
        inner.queue.push_back(port);
    }
}

/// Non thread-safe inner logic for TCP port pool.
#[derive(Debug, Default)]
struct TcpPortPoolInner {
    /// Remaining ports in the pool.
    queue: VecDeque<u16>,
}
