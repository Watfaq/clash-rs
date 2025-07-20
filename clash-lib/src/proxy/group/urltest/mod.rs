use std::{io, sync::atomic::AtomicU16};

use async_trait::async_trait;
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

pub struct Handler {
    opts: HandlerOptions,
    tolerance: u16,

    providers: Vec<ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,
    fastest_proxy_index: AtomicU16,
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
            fastest_proxy_index: AtomicU16::new(0),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    async fn fastest(&self, touch: bool) -> AnyOutboundHandler {
        let proxy_manager = self.proxy_manager.clone();

        let proxies = self.get_proxies(touch).await;
        let mut fastest = proxies
            .first()
            .unwrap_or_else(|| panic!("no proxy found for {}", self.name()));

        let mut fastest_delay = proxy_manager.last_delay(fastest.name()).await;
        let mut fast_not_exist = true;

        let current_fastest_index = std::cmp::min(
            self.fastest_proxy_index
                .load(std::sync::atomic::Ordering::Relaxed),
            proxies.len() as u16 - 1,
        );

        for proxy in proxies.iter().skip(1) {
            if proxy.name() == proxies[current_fastest_index as usize].name() {
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

            if current_fastest_index != u16::MAX
                || fast_not_exist
                || proxy_manager.alive(fastest.name()).await
                || proxy_manager
                    .last_delay(proxies[current_fastest_index as usize].name())
                    .await
                    > fastest_delay + self.tolerance
            {
                self.fastest_proxy_index.store(
                    proxies
                        .iter()
                        .position(|p| p.name() == fastest.name())
                        .unwrap() as u16,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        }

        trace!(
            fastest = %fastest.name(),
            delay = fastest_delay,
            "`{}` fastest",
            self.name(),
        );

        fastest.clone()
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

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}
