use std::{sync::Arc, time::Duration};

use futures::future;
use tokio::time::Interval;

use crate::common::providers::{
    fether::Fetcher, proxy_provider::ProxyProvider, ThreadSafeProviderVehicle,
};

use super::{healthcheck::HealthCheck, ThreadSafeProxy};

struct FileProviderInner {
    proxies: Vec<ThreadSafeProxy>,
}

struct FileProvider {
    fetcher: Fetcher<
        Box<dyn Fn(Vec<ThreadSafeProxy>) + Send + Sync + 'static>,
        Box<dyn Fn(&[u8]) -> anyhow::Result<Vec<ThreadSafeProxy>> + Send + Sync + 'static>,
    >,
    healthcheck: HealthCheck,
    inner: std::sync::Arc<tokio::sync::Mutex<FileProviderInner>>,
}

impl FileProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        mut hc: HealthCheck,
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
        })
    }
}

impl ProxyProvider for FileProvider {
    fn proxies(&self) -> Vec<crate::config::internal::proxy::OutboundProxy> {
        todo!()
    }

    fn touch(&self) {
        todo!()
    }

    fn healthcheck(&self) {
        todo!()
    }
}
