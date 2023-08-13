use std::io;

use crate::{
    app::{
        proxy_manager::{
            providers::proxy_provider::ThreadSafeProxyProvider, ThreadSafeProxyManager,
        },
        ThreadSafeDNSResolver,
    },
    config::internal::proxy::{OutboundGroupFallback, OutboundProxy},
    session::{Session, SocksAddr},
};

use super::{
    utils::provider_helper::get_proxies_from_providers, AnyOutboundDatagram, AnyOutboundHandler,
    AnyStream, CommonOption, OutboundHandler,
};

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub udp: bool,

    pub common_option: CommonOption,
}

#[derive(Clone)]
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
    fn proto(&self) -> OutboundProxy {
        OutboundProxy::ProxyGroup(
            crate::config::internal::proxy::OutboundGroupProtocol::Fallback(
                OutboundGroupFallback::default(),
            ),
        )
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
        unimplemented!("fallback proxy_stream")
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
