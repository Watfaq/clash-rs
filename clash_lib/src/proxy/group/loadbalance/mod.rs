mod helpers;

use std::{collections::HashMap, io, sync::Arc};

use erased_serde::Serialize;
use helpers::strategy_sticky_session;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            ProxyManager, providers::proxy_provider::ThreadSafeProxyProvider,
        },
    },
    config::internal::proxy::LoadBalanceStrategy,
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

use self::helpers::{StrategyFn, strategy_consistent_hashring, strategy_rr};

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
    pub strategy: LoadBalanceStrategy,
}

struct HandlerInner {
    strategy_fn: StrategyFn,
}

pub struct Handler {
    opts: HandlerOptions,

    providers: Vec<ThreadSafeProxyProvider>,

    inner: Arc<Mutex<HandlerInner>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalance")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        let strategy_fn = match opts.strategy {
            LoadBalanceStrategy::ConsistentHashing => strategy_consistent_hashring(),
            LoadBalanceStrategy::RoundRobin => strategy_rr(),
            LoadBalanceStrategy::StickySession => {
                strategy_sticky_session(proxy_manager)
            }
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

impl DialWithConnector for Handler {}

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

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let proxies = self.get_proxies(false).await;
        let proxy = (self.inner.lock().await.strategy_fn)(proxies, sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());
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
        let proxies = self.get_proxies(false).await;
        let proxy = (self.inner.lock().await.strategy_fn)(proxies, sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());
        proxy.connect_datagram(sess, resolver).await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let proxies = self.get_proxies(false).await;
        let proxy = (self.inner.lock().await.strategy_fn)(proxies, sess).await?;
        debug!("{} use proxy {}", self.name(), proxy.name());
        proxy
            .connect_stream_with_connector(sess, resolver, connector)
            .await
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = get_proxies_from_providers(&self.providers, false).await;

        let mut m = HashMap::new();
        m.insert("type".to_string(), Box::new(self.proto()) as _);

        m.insert(
            "all".to_string(),
            Box::new(all.iter().map(|x| x.name().to_owned()).collect::<Vec<_>>())
                as _,
        );
        m
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}
