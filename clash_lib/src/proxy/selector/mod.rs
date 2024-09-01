use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use erased_serde::Serialize;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    session::Session,
    Error,
};

use super::{
    utils::{provider_helper::get_proxies_from_providers, RemoteConnector},
    AnyOutboundHandler, ConnectorType, DialWithConnector, OutboundHandler,
    OutboundType,
};

#[async_trait]
pub trait SelectorControl {
    async fn select(&mut self, name: &str) -> Result<(), Error>;
    async fn current(&self) -> String;
}

pub type ThreadSafeSelectorControl = Arc<Mutex<dyn SelectorControl + Send + Sync>>;

struct HandlerInner {
    current: String,
}

#[derive(Default, Clone)]
pub struct HandlerOptions {
    pub shared_opts: super::options::HandlerSharedOptions,
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
        seleted: Option<String>,
    ) -> Self {
        let provider = providers.first().unwrap();
        let proxies = provider.read().await.proxies().await;
        let current = proxies.first().unwrap().name().to_owned();

        Self {
            opts,
            providers,
            inner: Arc::new(RwLock::new(HandlerInner {
                current: seleted.unwrap_or(current),
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
    async fn select(&mut self, name: &str) -> Result<(), Error> {
        let proxies = get_proxies_from_providers(&self.providers, false).await;
        if proxies.iter().any(|x| x.name() == name) {
            name.clone_into(&mut self.inner.write().await.current);
            Ok(())
        } else {
            Err(Error::Operation(format!("proxy {} not found", name)))
        }
    }

    async fn current(&self) -> String {
        self.inner.read().await.current.to_owned()
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Selector
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp && self.selected_proxy(false).await.support_udp().await
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let s = self
            .selected_proxy(true)
            .await
            .connect_stream(sess, resolver)
            .await;

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
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        self.selected_proxy(true)
            .await
            .connect_datagram(sess, resolver)
            .await
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
        let s = self
            .selected_proxy(true)
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
        self.selected_proxy(true)
            .await
            .connect_datagram_with_connector(sess, resolver, connector)
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
        self.opts.shared_opts.icon.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::{Mutex, RwLock};

    use crate::proxy::{
        mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
        selector::ThreadSafeSelectorControl,
    };

    #[tokio::test]
    async fn test_selector_control() {
        let mut mock_provider = MockDummyProxyProvider::new();
        mock_provider
            .expect_name()
            .return_const("provider1".to_owned());

        mock_provider.expect_proxies().returning(|| {
            let mut proxy1 = MockDummyOutboundHandler::new();
            proxy1.expect_name().return_const("provider1".to_owned());
            let mut proxy2 = MockDummyOutboundHandler::new();
            proxy2.expect_name().return_const("provider2".to_owned());
            vec![Arc::new(proxy1), Arc::new(proxy2)]
        });

        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                udp: false,
                ..Default::default()
            },
            vec![Arc::new(RwLock::new(mock_provider))],
            None,
        )
        .await;

        let selector_control =
            Arc::new(Mutex::new(handler.clone())) as ThreadSafeSelectorControl;
        let outbound_handler = Arc::new(handler);

        assert_eq!(
            selector_control.lock().await.current().await,
            "provider1".to_owned()
        );
        assert_eq!(
            outbound_handler.selected_proxy(false).await.name(),
            "provider1".to_owned()
        );

        selector_control
            .lock()
            .await
            .select("provider2")
            .await
            .unwrap();

        assert_eq!(
            selector_control.lock().await.current().await,
            "provider2".to_owned()
        );
        assert_eq!(
            outbound_handler.selected_proxy(false).await.name(),
            "provider2".to_owned()
        );

        let fail = selector_control.lock().await.select("provider3").await;
        assert!(fail.is_err());
    }
}
