use std::{collections::HashMap, io};

use erased_serde::Serialize;
use tracing::debug;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            providers::proxy_provider::ThreadSafeProxyProvider, ProxyManager,
        },
    },
    session::{Session, SocksAddr},
};

use super::{
    utils::provider_helper::get_proxies_from_providers, AnyOutboundHandler, CommonOption,
    OutboundHandler, OutboundType,
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
    proxy_manager: ProxyManager,
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
        proxy_manager: ProxyManager,
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
            if self.proxy_manager.alive(proxy.name()).await {
                debug!("`{}` fallback to `{}`", self.name(), proxy.name());
                return proxy.clone();
            }
        }
        proxies[0].clone()
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
    ) -> io::Result<BoxedChainedStream> {
        let proxy = self.find_alive_proxy(true).await;
        match proxy.connect_stream(sess, resolver).await {
            Ok(s) => {
                s.append_to_chain(self.name()).await;
                Ok(s)
            }
            Err(e) => Err(e),
        }
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let proxy = self.find_alive_proxy(true).await;
        proxy.connect_datagram(sess, resolver).await
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = get_proxies_from_providers(&self.providers, false).await;

        let mut m = HashMap::new();
        m.insert("type".to_string(), Box::new(self.proto()) as _);
        m.insert(
            "now".to_string(),
            Box::new(self.find_alive_proxy(false).await.name().to_owned()) as _,
        );
        m.insert(
            "all".to_string(),
            Box::new(all.iter().map(|x| x.name().to_owned()).collect::<Vec<_>>()) as _,
        );
        m
    }
}
