use std::fmt::Debug;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    config::internal::proxy::PROXY_DIRECT,
    proxy::{
        datagram::OutboundDatagramImpl,
        utils::{new_tcp_stream, new_udp_socket},
        OutboundHandler,
    },
    session::Session,
};

use async_trait::async_trait;
use serde::Serialize;

use super::{
    utils::RemoteConnector, ConnectorType, DialWithConnector, OutboundType,
};

#[derive(Serialize)]
pub struct Handler;

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Direct").finish()
    }
}

impl Handler {
    pub fn new() -> Self {
        Self
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        PROXY_DIRECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Direct
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let s = new_tcp_stream(
            resolver,
            sess.destination.host().as_str(),
            sess.destination.port(),
            sess.iface.as_ref(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        )
        .await?;

        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let d = new_udp_socket(
            None,
            sess.iface.as_ref(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        )
        .await
        .map(|x| OutboundDatagramImpl::new(x, resolver))?;

        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedStream> {
        let s = connector
            .connect_stream(
                resolver,
                sess.destination.host().as_str(),
                sess.destination.port(),
                sess.iface.as_ref(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                None,
            )
            .await?;
        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let d = connector
            .connect_datagram(
                resolver,
                None,
                &sess.destination,
                sess.iface.as_ref(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                None,
            )
            .await?;
        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }
}
