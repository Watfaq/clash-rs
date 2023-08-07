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
    proxy_registry: Arc<Mutex<ProxyManager>>,
    latency_test_url: String,
}

impl PlainProvider {
    pub fn new(
        name: String,
        proxies: Vec<AnyOutboundHandler>,
        proxy_registry: Arc<Mutex<ProxyManager>>,
        latency_test_url: String,
    ) -> anyhow::Result<Self> {
        if proxies.is_empty() {
            return Err(Error::InvalidConfig(format!("{}: proxies is empty", name)).into());
        }

        Ok(Self {
            name,
            proxies,
            proxy_registry,
            latency_test_url,
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
        todo!("PlainProvider::touch");
    }
    async fn healthcheck(&self) {
        self.proxy_registry
            .lock()
            .await
            .check(&self.proxies, &self.latency_test_url, None)
            .await;
    }
}
