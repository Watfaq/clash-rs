use std::{io, sync::Arc};

use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use tracing::{debug, error};

use crate::{
    app::{
        proxy_manager::providers::proxy_provider::ThreadSafeProxyProvider, ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    config::internal::proxy::{OutboundGroupRelay, OutboundProxy},
    proxy::utils::new_tcp_stream,
    session::{Session, SocksAddr},
};

use super::{
    utils::provider_helper::get_proxies_from_providers, AnyOutboundDatagram, AnyOutboundHandler,
    AnyStream, CommonOption, OutboundHandler,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: CommonOption,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
    ) -> AnyOutboundHandler {
        Arc::new(Self { opts, providers })
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        self.opts.name.as_str()
    }

    fn proto(&self) -> OutboundProxy {
        OutboundProxy::ProxyGroup(
            crate::config::internal::proxy::OutboundGroupProtocol::Relay(
                OutboundGroupRelay::default(),
            ),
        )
    }

    async fn remote_addr(&self) -> Option<SocksAddr> {
        None
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let proxies: Vec<AnyOutboundHandler> = stream::iter(self.get_proxies(true).await)
            .filter_map(|x| async {
                match x.remote_addr().await {
                    Some(_) => Some(x),
                    None => None,
                }
            })
            .collect()
            .await;

        match proxies.len() {
            0 => Err(new_io_error("no proxy available")),
            1 => {
                let proxy = proxies[0].clone();
                proxy.connect_stream(sess, resolver).await
            }
            _ => {
                let mut first = proxies[0].clone();
                let last = proxies[proxies.len() - 1].clone();

                let remote_addr = first.remote_addr().await.unwrap();

                let mut s = new_tcp_stream(
                    resolver.clone(),
                    remote_addr.host().as_str(),
                    remote_addr.port(),
                    None,
                )
                .await?;

                let mut next_sess = sess.clone();
                for i in 1..proxies.len() {
                    let proxy = proxies[i].clone();
                    error!(
                        "relay {} -> {} -> {} -> {}",
                        first.name(),
                        proxy.name(),
                        proxy.remote_addr().await.unwrap(),
                        proxies.len()
                    );
                    next_sess.destination =
                        proxy.remote_addr().await.expect("must have remote addr");
                    s = first.proxy_stream(s, &next_sess, resolver.clone()).await?;

                    first = proxy;
                }

                s = last.proxy_stream(s, &sess, resolver).await?;
                Ok(s)
            }
        }
    }

    async fn proxy_stream(
        &self,
        #[allow(unused_variables)] _s: AnyStream,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        Err(new_io_error("not implemented for Relay"))
    }

    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        Err(new_io_error("not implemented for Relay"))
    }
}
