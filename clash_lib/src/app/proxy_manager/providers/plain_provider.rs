use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{app::proxy_manager::healthcheck::HealthCheck, proxy::AnyOutboundHandler, Error};

use super::{proxy_provider::ProxyProvider, Provider, ProviderType, ProviderVehicleType};

struct Inner {
    hc: HealthCheck,
}

pub struct PlainProvider {
    name: String,
    proxies: Vec<AnyOutboundHandler>,
    inner: Arc<Mutex<Inner>>,
}

impl PlainProvider {
    pub fn new(
        name: String,
        proxies: Vec<AnyOutboundHandler>,
        mut hc: HealthCheck,
    ) -> anyhow::Result<Self> {
        if proxies.is_empty() {
            return Err(Error::InvalidConfig(format!("{}: proxies is empty", name)).into());
        }

        if hc.auto() {
            debug!("kicking off healthcheck: {}", name);
            hc.kick_off();
        }

        Ok(Self {
            name,
            proxies,
            inner: Arc::new(Mutex::new(Inner { hc })),
        })
    }
}

#[async_trait]
impl Provider for PlainProvider {
    fn name(&self) -> &str {
        &self.name
    }
    fn vehicle_type(&self) -> ProviderVehicleType {
        ProviderVehicleType::Compatible
    }
    fn typ(&self) -> ProviderType {
        ProviderType::Proxy
    }
    async fn initialize(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    async fn update(&self) -> std::io::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl ProxyProvider for PlainProvider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler> {
        self.proxies.clone()
    }

    async fn touch(&self) {
        self.inner.lock().await.hc.touch().await;
    }

    async fn healthcheck(&self) {
        self.inner.lock().await.hc.check().await;
    }
}
