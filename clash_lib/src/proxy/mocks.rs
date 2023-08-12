use mockall::mock;

use crate::app::proxy_manager::providers::{
    proxy_provider::ProxyProvider, Provider, ProviderType, ProviderVehicleType,
};

use super::AnyOutboundHandler;

mock! {
    pub DummyProxyProvider {}

    #[async_trait::async_trait]
    impl Provider for DummyProxyProvider {
        fn name(&self) -> &str;
        fn vehicle_type(&self) -> ProviderVehicleType;
        fn typ(&self) -> ProviderType;
        async fn initialize(&mut self) -> std::io::Result<()>;
        async fn update(&self) -> std::io::Result<()>;
    }

    #[async_trait::async_trait]
    impl ProxyProvider for DummyProxyProvider {
        async fn proxies(&self) -> Vec<AnyOutboundHandler>;
        async fn touch(&mut self);
        async fn healthcheck(&self);
    }
}
