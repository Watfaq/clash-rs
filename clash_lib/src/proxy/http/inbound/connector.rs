use crate::{
    Dispatcher,
    proxy::{AnyStream, ProxyError},
    session::{Network, Session, Type},
};
use futures::FutureExt;

use hyper::Uri;
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::duplex;

use super::proxy::maybe_socks_addr;

#[derive(Clone)]
pub struct Connector {
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
}

impl Connector {
    pub fn new(src: SocketAddr, dispatcher: Arc<Dispatcher>) -> Self {
        Self { src, dispatcher }
    }
}

impl tower::Service<Uri> for Connector {
    type Error = ProxyError;
    type Future =
        Pin<Box<dyn Future<Output = Result<AnyStream, Self::Error>> + Send>>;
    type Response = AnyStream;

    fn poll_ready(
        &mut self,
        #[allow(unused_variables)] cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, url: Uri) -> Self::Future {
        let src = self.src;
        let dispatcher = self.dispatcher.clone();

        let destination = maybe_socks_addr(&url);

        async move {
            let (left, right) = duplex(1024 * 1024);

            let sess = Session {
                network: Network::TCP,
                typ: Type::Http,
                source: src,
                destination: destination
                    .ok_or(ProxyError::InvalidUrl(url.to_string()))?,
                ..Default::default()
            };

            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, Box::new(right)).await;
            });

            Ok(Box::new(left) as _)
        }
        .boxed()
    }
}
