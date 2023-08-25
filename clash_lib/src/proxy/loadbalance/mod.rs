mod helpers;

use std::{io, sync::Arc};

use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    app::{
        proxy_manager::providers::proxy_provider::ThreadSafeProxyProvider, ThreadSafeDNSResolver,
    },
    config::internal::proxy::LoadBalanceStrategy,
    session::{Session, SocksAddr},
};

use self::helpers::{strategy_consistent_hashring, strategy_rr, StrategyFn};

use super::{
    utils::provider_helper::get_proxies_from_providers, AnyOutboundDatagram, AnyOutboundHandler,
    AnyStream, CommonOption, OutboundHandler, OutboundType,
};

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub udp: bool,
    pub strategy: LoadBalanceStrategy,

    pub common_option: CommonOption,
}

struct HandlerInner {
    strategy_fn: StrategyFn,
}

pub struct Handler {
    opts: HandlerOptions,

    providers: Vec<ThreadSafeProxyProvider>,

    inner: Arc<Mutex<HandlerInner>>,
}

impl Handler {
    pub fn new(opts: HandlerOptions, providers: Vec<ThreadSafeProxyProvider>) -> Self {
        let strategy_fn = match opts.strategy {
            LoadBalanceStrategy::ConsistentHashing => strategy_consistent_hashring(),
            LoadBalanceStrategy::RoundRobin => strategy_rr(),
        };

        Self {
            opts,
            providers,
            inner: Arc::new(Mutex::new(HandlerInner { strategy_fn })),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
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
        OutboundType::LoadBalance
    }

    /// The proxy remote address
    async fn remote_addr(&self) -> Option<SocksAddr> {
        None
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let proxies = self.get_proxies(false).await;
        let proxy = (self.inner.lock().await.strategy_fn)(proxies, &sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());
        proxy.connect_stream(sess, resolver).await
    }

    /// wraps a stream with outbound handler
    async fn proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let proxies = self.get_proxies(false).await;
        let proxy = (self.inner.lock().await.strategy_fn)(proxies, &sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());
        proxy.proxy_stream(s, sess, resolver).await
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        let proxies = self.get_proxies(false).await;
        let proxy = (self.inner.lock().await.strategy_fn)(proxies, &sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());
        proxy.connect_datagram(sess, resolver).await
    }
}
