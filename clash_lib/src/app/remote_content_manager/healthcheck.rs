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
    ) -> Self {
        Self {
            url,
            interval,
            lazy,
            proxy_manager,
            inner: Arc::new(tokio::sync::RwLock::new(HealCheckInner {
                last_check: tokio::time::Instant::now(),
                proxies,
                task_handle: None,
            })),
        }
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
            let mut ticker =
                tokio::time::interval(tokio::time::Duration::from_secs(interval));
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

    /// Forcefully starts the health check task if it's not already running,
    /// using a default interval if the configured interval is 0.
    pub async fn force_kick_off(&self, default_interval: u64) {
        let inner_guard = self.inner.write().await;
        if inner_guard.task_handle.is_some() {
            debug!("Healthcheck task already running for {}", self.url);
            return; // Already running
        }

        let interval_to_use = if self.interval > 0 {
            self.interval
        } else {
            default_interval
        };

        if interval_to_use == 0 {
            debug!(
                "Skipping forced healthcheck kickoff for {} as effective interval \
                 is 0",
                self.url
            );
            return; // Effective interval is 0, don't start timer
        }

        debug!(
            "Forcefully kicking off healthcheck for {} with interval {}",
            self.url, interval_to_use
        );

        // Drop write lock before spawning task
        drop(inner_guard);

        // Immediate check first
        let proxy_manager_clone = self.proxy_manager.clone();
        let url_clone = self.url.clone();
        let proxies_clone = self.inner.read().await.proxies.clone();
        tokio::spawn(async move {
            proxy_manager_clone
                .check(&proxies_clone, &url_clone, None)
                .await;
        });

        let inner_arc_clone = self.inner.clone();
        let proxy_manager_clone_timer = self.proxy_manager.clone();
        let url_clone_timer = self.url.clone();
        let lazy_clone = self.lazy; // Capture lazy flag

        let task_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(
                tokio::time::Duration::from_secs(interval_to_use),
            );
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        debug!("Forced healthcheck ticking: {}, lazy: {}", url_clone_timer, lazy_clone);
                        let inner_read = inner_arc_clone.read().await;
                        let proxies_timer = inner_read.proxies.clone();
                        let last_check_timer = inner_read.last_check;
                        drop(inner_read); // Drop read lock

                        let now = tokio::time::Instant::now();
                        if !lazy_clone || now.duration_since(last_check_timer).as_secs() >= interval_to_use {
                             debug!("Executing forced healthcheck for {}", url_clone_timer);
                            proxy_manager_clone_timer.check(&proxies_timer, &url_clone_timer, None).await;
                            let mut w = inner_arc_clone.write().await;
                            w.last_check = now;
                        } else {
                             debug!("Skipping lazy forced healthcheck for {}", url_clone_timer);
                        }
                    },
                }
            }
        });

        // Reacquire write lock to store handle
        let mut inner_guard_write = self.inner.write().await;
        inner_guard_write.task_handle = Some(Arc::new(task_handle));
        debug!("Forced healthcheck task started for {}", self.url);
    }
}
