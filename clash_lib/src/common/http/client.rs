use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::Future;

use http_body_util::Empty;
use hyper::Uri;
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection},
    },
    rt::TokioExecutor,
};
use tower::Service;
use watfaq_resolver::{AbstractResolver, Resolver};
use watfaq_state::Context as AppContext;
use watfaq_types::Stack;
use watfaq_utils::{which_ip_decision, which_stack_decision};

use crate::{common::tls::GLOBAL_ROOT_STORE, proxy::AnyStream};

#[derive(Clone)]
/// A LocalConnector that is generalised to connect to any url
pub struct LocalConnector {
    pub ctx: Arc<AppContext>,
    pub resolver: Arc<Resolver>,
}

impl Service<Uri> for LocalConnector {
    type Error = watfaq_error::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = AnyStream;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, remote: Uri) -> Self::Future {
        let host = remote
            .host()
            .unwrap_or_else(|| panic!("invalid url: {}", remote))
            .to_owned();

        let dns = self.resolver.clone();
        let ctx = self.ctx.clone();
        // FIXME remove Box pin
        Box::pin(async move {
            let remote_ip = dns.resolve(host.as_str(), false).await?;
            let remote_port =
                remote.port_u16().unwrap_or(match remote.scheme_str() {
                    None => 80,
                    Some(s) => match s {
                        "http" => 80,
                        "https" => 443,
                        _ => panic!("invalid url: {}", remote),
                    },
                });
            let remote_ip = which_ip_decision(&ctx, None, None, remote_ip)?;
            let remote_addr = SocketAddr::new(remote_ip, remote_port);

            ctx.protector
                .new_tcp(remote_addr, None)
                .await
                .map(|x| Box::new(x) as _)
        })
    }
}

impl Connection for AnyStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for AnyStream {
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

impl hyper::rt::Write for AnyStream {
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

pub type HttpClient =
    Client<hyper_rustls::HttpsConnector<LocalConnector>, Empty<Bytes>>;

pub fn new_http_client(
    ctx: Arc<AppContext>,
    resolver: Arc<Resolver>,
) -> std::io::Result<HttpClient> {
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(GLOBAL_ROOT_STORE.clone())
        .with_no_client_auth();
    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let connector = LocalConnector { ctx, resolver };

    let connector: hyper_rustls::HttpsConnector<LocalConnector> =
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(connector);

    Ok(Client::builder(TokioExecutor::new()).build(connector))
}
