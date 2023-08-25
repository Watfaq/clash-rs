use std::io;

use tracing::debug;

use crate::{
    app::{
        proxy_manager::{
            providers::proxy_provider::ThreadSafeProxyProvider, ThreadSafeProxyManager,
        },
        ThreadSafeDNSResolver,
    },
    session::{Session, SocksAddr},
};

use super::{
    utils::provider_helper::get_proxies_from_providers, AnyOutboundDatagram, AnyOutboundHandler,
    AnyStream, CommonOption, OutboundHandler, OutboundType,
};

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub udp: bool,

    pub common_option: CommonOption,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
    proxy_manager: ThreadSafeProxyManager,
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
        proxy_manager: ThreadSafeProxyManager,
    ) -> Self {
        Self {
            opts,
            providers,
            proxy_manager,
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    async fn find_alive_proxy(&self, touch: bool) -> AnyOutboundHandler {
        let proxies = self.get_proxies(touch).await;
        for proxy in proxies.iter() {
            if self.proxy_manager.lock().await.alive(proxy.name()).await {
                debug!("{} fastest {} is alive", self.name(), proxy.name());
                return proxy.clone();
            }
        }
        return proxies[0].clone();
    }
}

#[async_trait::async_trait]
impl OutboundHandler for Handler {
    /// The name of the outbound handler
    fn name(&self) -> &str {
        &self.opts.name
    }

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType {
        OutboundType::Fallback
    }

    /// The proxy remote address
    async fn remote_addr(&self) -> Option<SocksAddr> {
        self.find_alive_proxy(false).await.remote_addr().await
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        self.opts.udp || self.find_alive_proxy(false).await.support_udp().await
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let proxy = self.find_alive_proxy(true).await;
        proxy.connect_stream(sess, resolver).await
    }

    /// wraps a stream with outbound handler
    async fn proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let proxy = self.find_alive_proxy(true).await;
        proxy.proxy_stream(s, sess, resolver).await
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        let proxy = self.find_alive_proxy(true).await;
        proxy.connect_datagram(sess, resolver).await
    }
}
