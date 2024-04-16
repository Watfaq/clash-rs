use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use erased_serde::Serialize;
use tokio::sync::Mutex;
use tracing::trace;

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
    utils::{provider_helper::get_proxies_from_providers, RemoteConnector},
    AnyOutboundHandler, CommonOption, ConnectorType, OutboundHandler, OutboundType,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub name: String,
    pub udp: bool,

    pub common_option: CommonOption,
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

        return inner
            .fastest_proxy
            .as_ref()
            .unwrap_or(proxies.first().unwrap())
            .clone();
    }
}

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

    /// The proxy remote address
    async fn remote_addr(&self) -> Option<SocksAddr> {
        self.fastest(false).await.remote_addr().await
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
        let s = self
            .fastest(false)
            .await
            .connect_stream(sess, resolver)
            .await?;
        s.append_to_chain(self.name()).await;
        Ok(s)
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let d = self
            .fastest(false)
            .await
            .connect_datagram(sess, resolver)
            .await?;
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
        connector: &Box<dyn RemoteConnector>, // could've been a &dyn RemoteConnector, but mockall doesn't support that
    ) -> io::Result<BoxedChainedStream> {
        let s = self
            .fastest(true)
            .await
            .connect_stream_with_connector(sess, resolver, connector)
            .await?;

        s.append_to_chain(self.name()).await;
        Ok(s)
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = get_proxies_from_providers(&self.providers, false).await;

        let mut m = HashMap::new();
        m.insert("type".to_string(), Box::new(self.proto()) as _);
        m.insert(
            "now".to_string(),
            Box::new(self.fastest(false).await.name().to_owned()) as _,
        );
        m.insert(
            "all".to_string(),
            Box::new(all.iter().map(|x| x.name().to_owned()).collect::<Vec<_>>()) as _,
        );
        m
    }
}
