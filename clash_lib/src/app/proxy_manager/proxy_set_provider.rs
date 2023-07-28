use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::{future, TryFutureExt};
use tokio::sync::Mutex;

use crate::common::{
    errors::map_io_error,
    providers::{
        fether::Fetcher, proxy_provider::ProxyProvider, Provider, ThreadSafeProviderVehicle,
    },
};

use super::{healthcheck::HealthCheck, ProxyManager, ThreadSafeProxy};

struct FileProviderInner {
    proxies: Vec<ThreadSafeProxy>,
}

struct ProxySetProvider {
    fetcher: Fetcher<
        Box<dyn Fn(Vec<ThreadSafeProxy>) + Send + Sync + 'static>,
        Box<dyn Fn(&[u8]) -> anyhow::Result<Vec<ThreadSafeProxy>> + Send + Sync + 'static>,
    >,
    healthcheck: HealthCheck,
    inner: std::sync::Arc<tokio::sync::Mutex<FileProviderInner>>,
    proxy_registry: Arc<Mutex<ProxyManager>>,
}

impl ProxySetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        mut hc: HealthCheck,
        proxy_registry: Arc<Mutex<ProxyManager>>,
    ) -> anyhow::Result<Self> {
        if hc.auto() {
            hc.kick_off();
        }

        let inner = Arc::new(tokio::sync::Mutex::new(FileProviderInner {
            proxies: vec![],
        }));

        let inner_clone = inner.clone();

        let updater: Box<dyn Fn(Vec<ThreadSafeProxy>) + Send + Sync + 'static> =
            Box::new(move |input: Vec<ThreadSafeProxy>| -> () {
                let inner = inner_clone.clone();
                tokio::spawn(future::lazy(|_| async move {
                    let mut inner = inner.lock().await;
                    inner.proxies = input;
                }));
            });

        let parser: Box<
            dyn Fn(&[u8]) -> anyhow::Result<Vec<ThreadSafeProxy>> + Send + Sync + 'static,
        > = Box::new(|i: &[u8]| -> anyhow::Result<Vec<ThreadSafeProxy>> { Ok(vec![]) });

        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater.into()));
        Ok(Self {
            fetcher,
            healthcheck: hc,
            inner,
            proxy_registry,
        })
    }
}

#[async_trait]
impl Provider for ProxySetProvider {
    async fn name(&self) -> &str {
        self.fetcher.name()
    }

    async fn vehicle_type(&self) -> crate::common::providers::ProviderVehicleType {
        self.fetcher.vehicle_type().await
    }

    async fn typ(&self) -> crate::common::providers::ProviderType {
        crate::common::providers::ProviderType::Proxy
    }

    async fn initialize(&mut self) -> std::io::Result<()> {
        let ele = self.fetcher.initial().map_err(map_io_error).await?;
        if let Some(updater) = self.fetcher.on_update.clone().lock().await.as_ref() {
            updater(ele);
        }
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        let (ele, same) = self.fetcher.update().map_err(map_io_error).await?;
        if !same {
            if let Some(updater) = self.fetcher.on_update.clone().lock().await.as_ref() {
                updater(ele);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ProxyProvider for ProxySetProvider {
    async fn proxies(&self) -> Vec<ThreadSafeProxy> {
        self.inner
            .lock()
            .await
            .proxies
            .iter()
            .map(|x| x.clone())
            .collect()
    }

    async fn touch(&mut self) {
        self.healthcheck.touch().await;
    }

    async fn healthcheck(&self) {
        self.proxy_registry
            .lock()
            .await
            .check(&self.proxies().await)
            .await;
    }
}
