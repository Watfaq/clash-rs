use crate::app::dispatcher::{
    BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram, ChainedDatagramWrapper,
    ChainedStream, ChainedStreamWrapper,
};
use crate::app::dns::ThreadSafeDNSResolver;
use crate::config::internal::proxy::PROXY_DIRECT;
use crate::proxy::datagram::OutboundDatagramImpl;
use crate::proxy::utils::{new_tcp_stream, new_udp_socket};
use crate::proxy::{AnyOutboundHandler, AnyStream, OutboundHandler};
use crate::session::{Session, SocksAddr};

use async_trait::async_trait;
use serde::Serialize;
use std::sync::Arc;

use super::OutboundType;

#[derive(Serialize)]
pub struct Handler;

impl Handler {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> AnyOutboundHandler {
        Arc::new(Self)
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        PROXY_DIRECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Direct
    }

    async fn remote_addr(&self) -> Option<SocksAddr> {
        None
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
            None,
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
}
