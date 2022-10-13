use crate::config::internal::proxy::PROXY_DIRECT;
use crate::proxy::utils::new_tcp_stream;
use crate::proxy::{AnyOutboundHandler, AnyStream, OutboundHandler, ProxyChain};
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
        dns_client: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        new_tcp_stream(
            dns_client,
            sess.destination.host().as_str(),
            sess.destination.port(),
            None,
        )
        .await
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
