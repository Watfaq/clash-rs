use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::{
    app::proxy_manager::{healthcheck::HealthCheck, ProxyManager},
    proxy::AnyOutboundHandler,
    Error,
};

use super::{proxy_provider::ProxyProvider, Provider, ProviderType, ProviderVehicleType};

pub struct PlainProvider {
    name: String,
    proxies: Vec<AnyOutboundHandler>,
    healthcheck: HealthCheck,
    proxy_registry: Arc<Mutex<ProxyManager>>,
}

impl PlainProvider {
    pub fn new(
        name: String,
        proxies: Vec<AnyOutboundHandler>,
        mut healthcheck: HealthCheck,
        proxy_registry: Arc<Mutex<ProxyManager>>,
    ) -> anyhow::Result<Self> {
        if proxies.is_empty() {
            return Err(Error::InvalidConfig(format!("{}: proxies is empty", name)).into());
        }

        if healthcheck.auto() {
            healthcheck.kick_off();
        }

        Ok(Self {
            name,
            proxies,
            healthcheck,
            proxy_registry,
        })
    }
}

#[async_trait]
impl Provider for PlainProvider {
    async fn name(&self) -> &str {
        &self.name
    }
    async fn vehicle_type(&self) -> ProviderVehicleType {
        ProviderVehicleType::Compatible
    }
    async fn typ(&self) -> ProviderType {
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
    async fn touch(&mut self) {
        self.healthcheck.touch().await;
    }
    async fn healthcheck(&self) {
        self.proxy_registry.lock().await.check(&self.proxies).await;
    }
}
