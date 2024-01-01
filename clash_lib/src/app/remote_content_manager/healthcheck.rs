use std::sync::Arc;

use tokio::time::Instant;
use tracing::debug;

use crate::proxy::AnyOutboundHandler;

use super::ProxyManager;

struct HealCheckInner {
    last_check: Instant,
    proxies: Vec<AnyOutboundHandler>,
    task_handle: Option<Arc<tokio::task::JoinHandle<()>>>,
}

pub struct HealthCheck {
    url: String,
    interval: u64,
    lazy: bool,
    proxy_manager: ProxyManager,
    inner: Arc<tokio::sync::RwLock<HealCheckInner>>,
}

impl HealthCheck {
    pub fn new(
        proxies: Vec<AnyOutboundHandler>,
        url: String,
        interval: u64,
        lazy: bool,
        proxy_manager: ProxyManager,
    ) -> anyhow::Result<Self> {
        let health_check = Self {
            url,
            interval,
            lazy,
            proxy_manager,
            inner: Arc::new(tokio::sync::RwLock::new(HealCheckInner {
                last_check: tokio::time::Instant::now(),
                proxies,
                task_handle: None,
            })),
        };
        Ok(health_check)
    }

    pub async fn kick_off(&self) {
        let proxy_manager = self.proxy_manager.clone();
        let interval = self.interval;
        let lazy = self.lazy;
        let proxies = self.inner.read().await.proxies.clone();

        {
            let url = self.url.clone();
            let proxies = proxies.clone();
            tokio::spawn(async move {
                proxy_manager.check(&proxies, &url, None).await;
            });
        }

        let inner = self.inner.clone();
        let proxy_manager = self.proxy_manager.clone();
        let url = self.url.clone();
        let task_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(interval));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        debug!("healthcheck ticking: {}, lazy: {}", url, lazy);
                        let now = tokio::time::Instant::now();
                        let last_check = inner.read().await.last_check;
                        if !lazy || now.duration_since(last_check).as_secs() >= interval {
                            proxy_manager.check(&proxies, &url, None).await;
                            let mut w = inner.write().await;
                            w.last_check = now;
                        }
                    },
                }
            }
        });

        self.inner.write().await.task_handle = Some(Arc::new(task_handle));
    }

    pub async fn touch(&self) {
        self.inner.write().await.last_check = tokio::time::Instant::now();
    }

    pub async fn check(&self) {
        let proxies = self.inner.read().await.proxies.clone();
        self.proxy_manager.check(&proxies, &self.url, None).await;
    }

    pub async fn update(&self, proxies: Vec<AnyOutboundHandler>) {
        self.inner.write().await.proxies = proxies;
    }

    pub fn auto(&self) -> bool {
        self.interval != 0
    }
}
