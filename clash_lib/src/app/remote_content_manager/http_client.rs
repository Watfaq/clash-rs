use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::Future;
use hyper::Uri;

use hyper_util::client::legacy::connect::{Connected, Connection};
use tower::Service;

use crate::{
    app::{dispatcher::BoxedChainedStream, dns::ThreadSafeDNSResolver},
    proxy::AnyOutboundHandler,
    session::Session,
};

#[derive(Clone)]
/// A LocalConnector that has a enclosed AnyOutboundHandler for url test
pub struct LocalConnector(pub AnyOutboundHandler, pub ThreadSafeDNSResolver);

impl Service<Uri> for LocalConnector {
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = BoxedChainedStream;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, remote: Uri) -> Self::Future {
        let host = remote
            .host()
            .unwrap_or_else(|| panic!("invalid url: {}", remote))
            .to_owned();

        let port = remote.port_u16().unwrap_or(match remote.scheme_str() {
            None => 80,
            Some(s) => match s {
                "http" => 80,
                "https" => 443,
                _ => panic!("invalid url: {}", remote),
            },
        });

        let sess = Session {
            destination: (host, port)
                .try_into()
                .unwrap_or_else(|_| panic!("invalid url: {}", remote)),
            ..Default::default()
        };
        let handler = self.0.clone();
        let resolver = self.1.clone();

        Box::pin(async move { handler.connect_stream(&sess, resolver).await })
    }
}

impl Connection for BoxedChainedStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for BoxedChainedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let n = unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            match tokio::io::AsyncRead::poll_read(self, cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                other => return other,
            }
        };

        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for BoxedChainedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(self, cx)
    }
}
