use crate::config::internal::proxy::PROXY_DIRECT;
use crate::proxy::{AnyOutboundHandler, AnyStream, OutboundHandler, ProxyChain};
use crate::session::Session;
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
        PROXY_DIRECT
    }

    async fn connect_stream(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }
}

#[async_trait]
impl ProxyChain for Handler {
    async fn chain(&self, s: AnyStream, sess: &Session) -> io::Result<AnyStream> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }
}
