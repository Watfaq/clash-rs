use crate::config::internal::proxy::{
    OutboundProxy, OutboundProxyProtocol, PROXY_REJECT,
};
use crate::proxy::{
    AnyOutboundDatagram, AnyOutboundHandler, AnyStream, OutboundHandler, ProxyChain,
};
use crate::session::{Session, SocksAddr};
use crate::ThreadSafeDNSResolver;
use async_trait::async_trait;
use std::io;
use std::sync::Arc;

pub struct Handler;

impl Handler {
    pub fn new() -> AnyOutboundHandler {
        Arc::new(Self)
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        PROXY_REJECT
    }

    fn proto(&self) -> OutboundProxy {
        OutboundProxy::ProxyServer(OutboundProxyProtocol::Reject)
    }

    fn remote_addr(&self) -> Option<SocksAddr> {
        None
    }

    async fn connect_stream(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }

    async fn proxy_stream(
        &self,
        _s: AnyStream,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }

    async fn connect_datagram(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }
}

#[async_trait]
impl ProxyChain for Handler {
    async fn chain(&self, _s: AnyStream, _sess: &Session) -> io::Result<AnyStream> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }
}
