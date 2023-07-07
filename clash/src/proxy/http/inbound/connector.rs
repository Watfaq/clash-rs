use crate::proxy::http::inbound::maybe_socks_addr;
use crate::proxy::{AnyStream, ProxyError};
use crate::session::{Network, Session};
use crate::{Dispatcher};
use futures::FutureExt;

use hyper::Uri;
use std::future::Future;
use std::net::{SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::duplex;

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
    type Response = AnyStream;
    type Error = ProxyError;
    type Future = Pin<Box<dyn Future<Output = Result<AnyStream, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        #[allow(unused_variables)] cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, url: Uri) -> Self::Future {
        let src = self.src.clone();
        let dispatcher = self.dispatcher.clone();

        let destination = maybe_socks_addr(&url);

        async move {
            let (left, right) = duplex(1024 * 1024);

            let sess = Session {
                network: Network::HTTP,
                source: src,
                destination: destination.ok_or(ProxyError::InvalidUrl(url.to_string()))?,
                ..Default::default()
            };

            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, Box::new(right) as _).await;
            });

            Ok(Box::new(left) as _)
        }
        .boxed()
    }
}
