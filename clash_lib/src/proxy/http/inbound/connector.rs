use crate::{
    Dispatcher,
    proxy::ProxyError,
    session::{Network, Session, Type},
};
use futures::FutureExt;

use hyper::Uri;
use hyper_util::{client::legacy::connect::Connected, rt::TokioIo};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{DuplexStream, duplex};

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

struct IoWrap(TokioIo<DuplexStream>);
impl hyper_util::client::legacy::connect::Connection for IoWrap {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for IoWrap {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for IoWrap {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl tower::Service<Uri> for Connector {
    type Error = ProxyError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = IoWrap;

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
                network: Network::Tcp,
                typ: Type::Http,
                source: src,
                destination: destination
                    .ok_or(ProxyError::InvalidUrl(url.to_string()))?,
                ..Default::default()
            };

            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, Box::new(right)).await;
            });

            Ok(IoWrap(TokioIo::new(left)))
        }
        .boxed()
    }
}
