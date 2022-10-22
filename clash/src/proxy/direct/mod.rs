use crate::config::internal::proxy::PROXY_DIRECT;
use crate::proxy::datagram::OutboundDatagramImpl;
use crate::proxy::utils::{new_tcp_stream, new_udp_socket};
use crate::proxy::{
    AnyOutboundDatagram, AnyOutboundHandler, AnyStream, OutboundHandler, ProxyChain,
};
use crate::session::Session;
use crate::ThreadSafeDNSResolver;
use async_trait::async_trait;
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
        PROXY_DIRECT
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        new_tcp_stream(
            resolver,
            sess.destination.host().as_str(),
            sess.destination.port(),
            None,
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyOutboundDatagram> {
        new_udp_socket(None, sess.iface.as_ref())
            .await
            .map(|x| OutboundDatagramImpl::new(x, resolver))
    }
}

#[async_trait]
impl ProxyChain for Handler {
    async fn chain(
        &self,
        s: AnyStream,
        #[allow(unused_variables)] sess: &Session,
    ) -> std::io::Result<AnyStream> {
        Ok(s)
    }
}
