use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use erased_serde::Serialize;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    app::{
        proxy_manager::providers::proxy_provider::ThreadSafeProxyProvider, ThreadSafeDNSResolver,
    },
    session::{Session, SocksAddr},
    Error,
};

use super::{
    utils::provider_helper::get_proxies_from_providers, AnyOutboundDatagram, AnyOutboundHandler,
    AnyStream, CommonOption, OutboundHandler, OutboundType,
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
    pub name: String,
    pub udp: bool,

    pub common_option: CommonOption,
}

#[derive(Clone)]
pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
    inner: Arc<Mutex<HandlerInner>>,
}

impl Handler {
    pub async fn new(opts: HandlerOptions, providers: Vec<ThreadSafeProxyProvider>) -> Self {
        let current = providers
            .first()
            .unwrap()
            .lock()
            .await
            .proxies()
            .await
            .first()
            .unwrap()
            .name()
            .to_owned();
        Self {
            opts,
            providers,
            inner: Arc::new(Mutex::new(HandlerInner { current })),
        }
    }

    async fn selected_proxy(&self, touch: bool) -> AnyOutboundHandler {
        let proxies = get_proxies_from_providers(&self.providers, touch).await;
        for proxy in proxies {
            if proxy.name() == self.inner.lock().await.current {
                debug!("{} selected {}", self.name(), proxy.name());
                return proxy;
            }
        }
        unreachable!("selected proxy not found")
    }
}

#[async_trait]
impl SelectorControl for Handler {
    async fn select(&mut self, name: &str) -> Result<(), Error> {
        let proxies = get_proxies_from_providers(&self.providers, false).await;
        if proxies.iter().any(|x| x.name() == name) {
            self.inner.lock().await.current = name.to_owned();
            Ok(())
        } else {
            Err(Error::Operation(format!("proxy {} not found", name)))
        }
    }

    async fn current(&self) -> String {
        let inner = self.inner.lock().await.current.to_owned();
        inner
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Select
    }

    async fn remote_addr(&self) -> Option<SocksAddr> {
        self.selected_proxy(false).await.remote_addr().await
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp && self.selected_proxy(false).await.support_udp().await
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        self.selected_proxy(true)
            .await
            .connect_stream(sess, resolver)
            .await
    }

    async fn proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        self.selected_proxy(true)
            .await
            .proxy_stream(s, sess, resolver)
            .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        self.selected_proxy(true)
            .await
            .connect_datagram(sess, resolver)
            .await
    }

    /// for API
    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = get_proxies_from_providers(&self.providers, false).await;

        let mut m = HashMap::new();
        m.insert("type".to_string(), Box::new(self.proto()) as _);
        m.insert(
            "now".to_string(),
            Box::new(self.inner.lock().await.current.clone()) as _,
        );
        m.insert(
            "all".to_string(),
            Box::new(all.iter().map(|x| x.name().to_owned()).collect::<Vec<_>>()) as _,
        );
        m
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Mutex;

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
                common_option: super::CommonOption::default(),
            },
            vec![Arc::new(Mutex::new(mock_provider))],
        )
        .await;

        let selector_control = Arc::new(Mutex::new(handler.clone())) as ThreadSafeSelectorControl;
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
