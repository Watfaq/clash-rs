use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use erased_serde::Serialize;
use futures::stream::{self, StreamExt};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    common::errors::new_io_error,
    proxy::utils::new_tcp_stream,
    session::{Session, SocksAddr},
};

use super::{
    utils::provider_helper::get_proxies_from_providers, AnyOutboundHandler, AnyStream,
    CommonOption, OutboundHandler, OutboundType,
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
    #[allow(clippy::new_ret_no_self)]
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

    fn proto(&self) -> OutboundType {
        OutboundType::Relay
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
    ) -> io::Result<BoxedChainedStream> {
        let proxies: Vec<AnyOutboundHandler> = stream::iter(self.get_proxies(true).await)
            .filter_map(|x| async { x.remote_addr().await.map(|_| x) })
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
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    None,
                )
                .await?;

                let mut next_sess = sess.clone();
                for proxy in proxies.iter().skip(1) {
                    let proxy = proxy.clone();
                    next_sess.destination =
                        proxy.remote_addr().await.expect("must have remote addr");
                    s = first.proxy_stream(s, &next_sess, resolver.clone()).await?;

                    first = proxy;
                }

                s = last.proxy_stream(s, sess, resolver).await?;
                let chained = ChainedStreamWrapper::new(s);
                chained.append_to_chain(self.name()).await;
                Ok(Box::new(chained))
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
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let proxies: Vec<AnyOutboundHandler> = stream::iter(self.get_proxies(true).await)
            .filter_map(|x| async { x.remote_addr().await.map(|_| x) })
            .collect()
            .await;

        match proxies.len() {
            0 => Err(new_io_error("no proxy available")),
            1 => {
                let proxy = proxies[0].clone();
                proxy.connect_datagram(sess, resolver).await
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
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    None,
                )
                .await?;

                let mut next_sess = sess.clone();
                for proxy in proxies.iter().skip(1) {
                    let proxy = proxy.clone();
                    next_sess.destination =
                        proxy.remote_addr().await.expect("must have remote addr");
                    s = first.connect_datagram(&next_sess, resolver.clone()).await?;

                    first = proxy;
                }

                s = last.proxy_stream(s, sess, resolver).await?;
                let chained = ChainedStreamWrapper::new(s);
                chained.append_to_chain(self.name()).await;
                Ok(Box::new(chained))
            }
        }
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
