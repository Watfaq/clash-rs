use std::{io, sync::Arc};

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::trace;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            ProxyManager, providers::proxy_provider::ThreadSafeProxyProvider,
        },
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::GroupProxyAPIResponse,
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

struct HandlerInner {
    fastest_proxy: Option<AnyOutboundHandler>,
}

pub struct Handler {
    opts: HandlerOptions,
    tolerance: u16,

    providers: Vec<ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,

    inner: Arc<Mutex<HandlerInner>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlTest")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        tolerance: u16,
        providers: Vec<ThreadSafeProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            opts,
            tolerance,
            providers,
            proxy_manager,
            inner: Arc::new(Mutex::new(HandlerInner {
                fastest_proxy: None,
            })),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    async fn fastest(&self, touch: bool) -> AnyOutboundHandler {
        let proxy_manager = self.proxy_manager.clone();
        let mut inner = self.inner.lock().await;

        let proxies = self.get_proxies(touch).await;
        let mut fastest = proxies
            .first()
            .unwrap_or_else(|| panic!("no proxy found for {}", self.name()));

        let mut fastest_delay = proxy_manager.last_delay(fastest.name()).await;
        let mut fast_not_exist = true;

        for proxy in proxies.iter().skip(1) {
            if inner.fastest_proxy.is_some()
                && proxy.name() == inner.fastest_proxy.as_ref().unwrap().name()
            {
                fast_not_exist = false;
            }

            if !proxy_manager.alive(proxy.name()).await {
                continue;
            }

            let delay = proxy_manager.last_delay(proxy.name()).await;
            if delay < fastest_delay {
                fastest = proxy;
                fastest_delay = delay;
            }

            if inner.fastest_proxy.is_some()
                || fast_not_exist
                || proxy_manager.alive(fastest.name()).await
                || proxy_manager
                    .last_delay(inner.fastest_proxy.as_ref().unwrap().name())
                    .await
                    > fastest_delay + self.tolerance
            {
                inner.fastest_proxy = Some(fastest.clone());
            }
        }

        trace!(
            "`{}` fastest is `{}` - delay {}",
            self.name(),
            fastest.name(),
            fastest_delay
        );

        inner
            .fastest_proxy
            .as_ref()
            .unwrap_or(proxies.first().unwrap())
            .clone()
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    /// The name of the outbound handler
    fn name(&self) -> &str {
        &self.opts.name
    }

    /// The protocol of the outbound handler
    fn proto(&self) -> OutboundType {
        OutboundType::UrlTest
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        self.opts.udp || self.fastest(false).await.support_udp().await
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let fastest = self.fastest(false).await;
        let s = fastest.connect_stream(sess, resolver).await?;
        s.append_to_chain(self.name()).await;
        s.append_to_chain(fastest.name()).await;
        Ok(s)
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let fastest = self.fastest(false).await;
        let d = fastest.connect_datagram(sess, resolver).await?;
        d.append_to_chain(self.name()).await;
        d.append_to_chain(fastest.name()).await;
        Ok(d)
    }

    async fn support_connector(&self) -> ConnectorType {
        self.fastest(false).await.support_connector().await
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let s = self
            .fastest(true)
            .await
            .connect_stream_with_connector(sess, resolver, connector)
            .await?;

        s.append_to_chain(self.name()).await;
        Ok(s)
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        self.fastest(true)
            .await
            .connect_datagram_with_connector(sess, resolver, connector)
            .await
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler> {
        Handler::get_proxies(self, false).await
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        Some(self.fastest(false).await)
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}
