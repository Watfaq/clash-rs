use crate::app::dispatcher::{BoxedChainedDatagram, BoxedChainedStream};
use crate::app::dns::ThreadSafeDNSResolver;
use crate::config::internal::proxy::PROXY_REJECT;
use crate::proxy::{AnyOutboundHandler, AnyStream, OutboundHandler};
use crate::session::{Session, SocksAddr};
use async_trait::async_trait;
use serde::Serialize;
use std::io;
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
        PROXY_REJECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Reject
    }

    async fn remote_addr(&self) -> Option<SocksAddr> {
        None
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }

    async fn connect_datagram(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }
}
