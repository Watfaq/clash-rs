mod helpers;

use std::{collections::HashMap, io, sync::Arc};

use erased_serde::Serialize;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    config::internal::proxy::LoadBalanceStrategy,
    session::{Session, SocksAddr},
};

use self::helpers::{strategy_consistent_hashring, strategy_rr, StrategyFn};

use super::{
    utils::provider_helper::get_proxies_from_providers, AnyOutboundHandler, CommonOption,
    ConnectorType, OutboundHandler, OutboundType,
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
        ConnectorType::None
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = get_proxies_from_providers(&self.providers, false).await;

        let mut m = HashMap::new();
        m.insert("type".to_string(), Box::new(self.proto()) as _);

        m.insert(
            "all".to_string(),
            Box::new(all.iter().map(|x| x.name().to_owned()).collect::<Vec<_>>()) as _,
        );
        m
    }
}
