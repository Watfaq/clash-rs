use std::{default, io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;

use crate::{
    app::{
        proxy_manager::{ProxyManager, ThreadSafeProxy},
        ThreadSafeDNSResolver,
    },
    common::{
        errors::new_io_error,
        providers::proxy_provider::{ProxyProvider, ThreadSafeProxyProvider},
    },
    config::internal::proxy::{OutboundGroupRelay, OutboundProxy},
    session::{Session, SocksAddr},
};

use super::{AnyOutboundDatagram, AnyOutboundHandler, AnyStream, CommonOption, OutboundHandler};

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

    fn get_proxies(&self) -> Vec<ThreadSafeProxy> {
        todo!()
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

    fn remote_addr(&self) -> Option<SocksAddr> {
        None
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let proxies: Vec<ThreadSafeProxy> = self
            .get_proxies()
            .into_iter()
            .filter(|x| match x.remote_addr() {
                Some(_) => true,
                None => false,
            })
            .collect();

        match proxies.len() {
            0 => Err(new_io_error("no proxy available")),
            1 => {
                let proxy = proxies[0].clone();
                proxy.connect_stream(sess, resolver).await
            }
            _ => {
                let first = proxies[0].clone();

                let mut s = first.connect_stream(sess, resolver.clone()).await?;
                let mut sess = sess.clone();
                for i in 1..proxies.len() - 1 {
                    let proxy = proxies[i].clone();
                    sess.destination = proxy.remote_addr().expect("must have remote addr");
                    s = proxy.proxy_stream(s, &sess, resolver.clone()).await?;
                }
                Ok(s)
            }
        }
    }

    async fn proxy_stream(
        &self,
        #[allow(unused_variables)] s: AnyStream,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        Err(new_io_error("not implemented for Relay"))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        todo!()
    }
}
