use std::{collections::HashMap, io};

use erased_serde::Serialize;
use mockall::mock;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::{
            proxy_provider::ProxyProvider, Provider, ProviderType, ProviderVehicleType,
        },
    },
    session::{Session, SocksAddr},
};

use super::{AnyOutboundHandler, OutboundHandler, OutboundType};

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
    pub DummyOutboundHandler {}

    #[async_trait::async_trait]
    impl OutboundHandler for DummyOutboundHandler {
        /// The name of the outbound handler
        fn name(&self) -> &str;

        /// The protocol of the outbound handler
        /// only contains Type information, do not rely on the underlying value
        fn proto(&self) -> OutboundType;

        /// The proxy remote address
        async fn remote_addr(&self) -> Option<SocksAddr>;

        /// whether the outbound handler support UDP
        async fn support_udp(&self) -> bool;

        /// connect to remote target via TCP
        async fn connect_stream(
            &self,
            sess: &Session,
            resolver: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedStream>;


        /// connect to remote target via UDP
        async fn connect_datagram(
            &self,
            sess: &Session,
            resolver: ThreadSafeDNSResolver,
        ) -> io::Result<BoxedChainedDatagram>;

        /// relay related
        async fn support_connector(&self) -> crate::proxy::ConnectorType;

        async fn connect_stream_with_connector(
            &self,
            sess: &Session,
            resolver: ThreadSafeDNSResolver,
            connector: &Box<dyn crate::proxy::utils::RemoteConnector>,
        ) -> io::Result<BoxedChainedStream>;

        async fn connect_datagram_with_connector(
            &self,
            sess: &Session,
            resolver: ThreadSafeDNSResolver,
            connector: &Box<dyn crate::proxy::utils::RemoteConnector>,
        ) -> io::Result<BoxedChainedDatagram>;
    }
}
