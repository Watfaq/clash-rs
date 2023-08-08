use std::io;

use async_trait::async_trait;

use crate::{
    app::{
        proxy_manager::providers::proxy_provider::ThreadSafeProxyProvider, ThreadSafeDNSResolver,
    },
    config::internal::proxy::{OutboundGroupSelect, OutboundProxy},
    session::{Session, SocksAddr},
    Error,
};

use super::{
    utils::provider_helper::get_proxies_from_providers, AnyOutboundDatagram, AnyOutboundHandler,
    AnyStream, CommonOption, OutboundHandler,
};

#[async_trait]
pub trait SelectorControl {
    async fn select(&mut self, name: &str) -> Result<(), Error>;
    fn current(&self) -> &str;
}

pub struct HandlerOptions {
    pub name: String,
    pub udp: bool,

    pub common_option: CommonOption,
}

pub struct Handler {
    opts: HandlerOptions,
    current: String,
    providers: Vec<ThreadSafeProxyProvider>,
}

impl Handler {
    pub async fn new(opts: HandlerOptions, providers: Vec<ThreadSafeProxyProvider>) -> Self {
        let current = providers.first().unwrap().lock().await.name().to_owned();
        Self {
            opts,
            current,
            providers,
        }
    }

    async fn selected_proxy(&self, touch: bool) -> AnyOutboundHandler {
        let proxies = get_proxies_from_providers(&self.providers, touch).await;
        proxies
            .into_iter()
            .find(|x| x.name() == self.current)
            .unwrap()
    }
}

#[async_trait]
impl SelectorControl for Handler {
    async fn select(&mut self, name: &str) -> Result<(), Error> {
        let proxies = get_proxies_from_providers(&self.providers, true).await;
        if proxies.iter().any(|x| x.name() == name) {
            self.current = name.to_owned();
            Ok(())
        } else {
            Err(Error::Operation(format!("proxy {} not found", name)))
        }
    }

    fn current(&self) -> &str {
        &self.current
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundProxy {
        OutboundProxy::ProxyGroup(
            crate::config::internal::proxy::OutboundGroupProtocol::Select(
                OutboundGroupSelect::default(),
            ),
        )
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
        unimplemented!("proxy_stream not implemented")
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
}
