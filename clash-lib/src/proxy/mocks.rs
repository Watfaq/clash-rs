use std::{collections::HashMap, io};

use erased_serde::Serialize;
use mockall::mock;

use super::{AnyOutboundHandler, DialWithConnector, OutboundHandler, OutboundType};
use crate::{
    app::{
        dispatcher::{BoxedInstrumentedDatagram, BoxedInstrumentedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::{
            Provider, ProviderType, ProviderVehicleType,
            proxy_provider::ProxyProvider,
        },
    },
    session::Session,
};

mock! {
    pub DummyProxyProvider {}

    #[async_trait::async_trait]
    impl Provider for DummyProxyProvider {
        fn name(&self) -> &str;
        fn vehicle_type(&self) -> ProviderVehicleType;
        fn typ(&self) -> ProviderType;
        async fn initialize(&self) -> std::io::Result<()>;
        async fn update(&self) -> std::io::Result<()>;

        async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>>;

    }

    #[async_trait::async_trait]
    impl ProxyProvider for DummyProxyProvider {
        async fn proxies(&self) -> Vec<AnyOutboundHandler>;
        async fn touch(&self);
        async fn healthcheck(&self);
    }
}

mock! {
    #[derive(Debug)]
    pub DummyOutboundHandler {}

    #[async_trait::async_trait]
    impl OutboundHandler for DummyOutboundHandler {
        /// The name of the outbound handler
        fn name(&self) -> &str;

        /// The protocol of the outbound handler
        /// only contains Type information, do not rely on the underlying value
        fn proto(&self) -> OutboundType;

        /// whether the outbound handler support UDP
        async fn support_udp(&self) -> bool;

        /// connect to remote target via TCP
        async fn connect_stream(
            &self,
            sess: &Session,
            resolver: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedInstrumentedStream>;


        /// connect to remote target via UDP
        async fn connect_datagram(
            &self,
            sess: &Session,
            resolver: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedInstrumentedDatagram>;

        /// relay related
        async fn support_connector(&self) -> crate::proxy::ConnectorType;
    }

    impl DialWithConnector for DummyOutboundHandler {}
}
