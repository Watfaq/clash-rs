use std::sync::Arc;

use tokio::{sync::Mutex, time::Instant};

use crate::proxy::AnyOutboundHandler;

use super::ProxyManager;

pub type ThreadSafeHealthCheck = Arc<Mutex<HealthCheck>>;

struct HealCheckInner {
    last_check: Instant,
}

pub struct HealthCheck {
    proxies: Vec<AnyOutboundHandler>,
    url: String,
    interval: u64,
    lazy: bool,
    latency_manager: Arc<Mutex<ProxyManager>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    inner: Arc<tokio::sync::Mutex<HealCheckInner>>,
}

impl HealthCheck {
    pub fn new(
        proxies: Vec<AnyOutboundHandler>,
        url: String,
        interval: u64,
        lazy: bool,
        latency_manager: Arc<Mutex<ProxyManager>>,
    ) -> anyhow::Result<Self> {
        let health_check = Self {
            proxies,
            url,
            interval,
            lazy,
            latency_manager,
            task_handle: None,
            inner: Arc::new(tokio::sync::Mutex::new(HealCheckInner {
                last_check: tokio::time::Instant::now(),
            })),
        };
        Ok(health_check)
    }

    pub fn kick_off(&mut self) {
        let latency_manager = self.latency_manager.clone();
        let interval = self.interval;
        let lazy = self.lazy;
        let proxies = self.proxies.clone();

        let url = self.url.clone();
        tokio::spawn(async move {
            latency_manager
                .lock()
                .await
                .check(&proxies, &url, None)
                .await;
        });

        let inner = self.inner.clone();
        let proxies = self.proxies.clone();
        let latency_manager = self.latency_manager.clone();
        let url = self.url.clone();
        let task_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(interval));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let now = tokio::time::Instant::now();
                        if !lazy || now.duration_since(inner.lock().await.last_check).as_secs() >= interval {
                            latency_manager.lock().await.check(&proxies, &url, None).await;
                            inner.lock().await.last_check = now;
                        }
                    },
                }
            }
        });

        self.task_handle = Some(task_handle);
    }

    pub async fn touch(&mut self) {
        self.inner.lock().await.last_check = tokio::time::Instant::now();
    }

    pub async fn check(&mut self) {
        self.latency_manager
            .lock()
            .await
            .check(&self.proxies, &self.url, None)
            .await;
    }

    fn stop(&mut self) {
        if let Some(task_handle) = self.task_handle.take() {
            task_handle.abort();
        }
    }

    fn update(&mut self, proxies: Vec<AnyOutboundHandler>) {
        self.proxies = proxies;
    }

    pub fn auto(&self) -> bool {
        self.interval != 0
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}
