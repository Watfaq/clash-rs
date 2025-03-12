use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use erased_serde::Serialize;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;
use watfaq_config::OutboundCommonOptions;
use watfaq_error::Result;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    proxy::{
        AbstractOutboundHandler, AnyOutboundHandler, ConnectorType, OutboundType,
        utils::{AbstractDialer, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

#[async_trait]
pub trait SelectorControl {
    async fn select(&mut self, name: &str) -> Result<()>;
    async fn current(&self) -> String;
}

pub type ThreadSafeSelectorControl = Arc<Mutex<dyn SelectorControl + Send + Sync>>;

struct HandlerInner {
    current: String,
}

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub common_opts: OutboundCommonOptions,
    pub name: String,
    pub udp: bool,
}

#[derive(Clone)]
pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
    inner: Arc<RwLock<HandlerInner>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Selector")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub async fn new(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
        selected: Option<String>,
    ) -> Self {
        let provider = providers.first().unwrap();
        let proxies = provider.read().await.proxies().await;
        let current = proxies.first().unwrap().name().to_owned();

        Self {
            opts,
            providers,
            inner: Arc::new(RwLock::new(HandlerInner {
                current: selected.unwrap_or(current),
            })),
        }
    }

    async fn selected_proxy(&self, touch: bool) -> AnyOutboundHandler {
        let proxies = get_proxies_from_providers(&self.providers, touch).await;
        let current = &self.inner.read().await.current;
        for proxy in proxies.iter() {
            if proxy.name() == current {
                debug!("`{}` selected `{}`", self.name(), proxy.name());
                return proxy.clone();
            }
        }
        debug!("selected proxy `{}` not found", current);
        // in the case the selected proxy is not found(stale cache), return the
        // first one
        proxies.first().unwrap().clone()
    }
}

#[async_trait]
impl SelectorControl for Handler {
    async fn select(&mut self, name: &str) -> Result<()> {
        let proxies = get_proxies_from_providers(&self.providers, false).await;
        if proxies.iter().any(|x| x.name() == name) {
            name.clone_into(&mut self.inner.write().await.current);
            Ok(())
        } else {
            Err(anyhow!("proxy {} not found", name))
        }
    }

    async fn current(&self) -> String {
        self.inner.read().await.current.to_owned()
    }
}

#[async_trait]
impl AbstractOutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Selector
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp && self.selected_proxy(false).await.support_udp().await
    }

    async fn connect_stream(&self, sess: &Session) -> Result<BoxedChainedStream> {
        let s = self.selected_proxy(true).await.connect_stream(sess).await;

        match s {
            Ok(s) => {
                s.append_to_chain(self.name()).await;
                Ok(s)
            }
            Err(e) => Err(e),
        }
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
    ) -> Result<BoxedChainedDatagram> {
        self.selected_proxy(true).await.connect_datagram(sess).await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        connector: &dyn AbstractDialer,
    ) -> Result<BoxedChainedStream> {
        let s = self
            .selected_proxy(true)
            .await
            .connect_stream_with_connector(sess, connector)
            .await?;

        s.append_to_chain(self.name()).await;
        Ok(s)
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        connector: &dyn AbstractDialer,
    ) -> Result<BoxedChainedDatagram> {
        self.selected_proxy(true)
            .await
            .connect_datagram_with_connector(sess, connector)
            .await
    }

    /// for API
    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = get_proxies_from_providers(&self.providers, false).await;

        let mut m = HashMap::new();
        m.insert("type".to_string(), Box::new(self.proto()) as _);
        m.insert("now".to_string(), Box::new(self.current().await) as _);
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
