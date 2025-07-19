use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::Future;
use hyper::Uri;

use hyper_util::client::legacy::connect::{Connected, Connection};
use tower::Service;
use tracing::instrument;

use crate::{
    app::{
        dispatcher::BoxedChainedStream, dns::ThreadSafeDNSResolver,
        net::OutboundInterface,
    },
    print_and_exit,
    proxy::AnyOutboundHandler,
    session::Session,
};

#[derive(Clone)]
/// A ConnectorWithOutbound that has a enclosed AnyOutboundHandler for url test
pub struct ConnectorWithOutbound {
    outbound_handler: AnyOutboundHandler,
    dns_resolver: ThreadSafeDNSResolver,
    iface: Option<OutboundInterface>,
}
impl ConnectorWithOutbound {
    pub fn new(
        outbound: AnyOutboundHandler,
        dns_resolver: ThreadSafeDNSResolver,
        iface: Option<OutboundInterface>,
    ) -> Self {
        Self {
            outbound_handler: outbound,
            dns_resolver,
            iface,
        }
    }
}

impl Service<Uri> for ConnectorWithOutbound {
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = BoxedChainedStream;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[instrument(skip(self))]
    fn call(&mut self, remote: Uri) -> Self::Future {
        let host = remote
            .host()
            .unwrap_or_else(|| print_and_exit!("invalid url: {}", remote))
            .to_owned();

        let port = remote.port_u16().unwrap_or(match remote.scheme_str() {
            None => 80,
            Some(s) => match s {
                "http" => 80,
                "https" => 443,
                _ => print_and_exit!("invalid url: {}", remote),
            },
        });

        let sess = Session {
            destination: (host, port)
                .try_into()
                .unwrap_or_else(|_| print_and_exit!("invalid url: {}", remote)),
            iface: self.iface.clone(),
            ..Default::default()
        };
        let handler = self.outbound_handler.clone();
        let resolver = self.dns_resolver.clone();

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
