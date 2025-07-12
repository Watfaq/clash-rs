use std::{
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

use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::tls::GLOBAL_ROOT_STORE,
    print_and_exit,
    proxy::{AnyStream, utils::new_tcp_stream},
};

#[derive(Clone)]
/// A LocalConnector that is generalised to connect to any url
pub struct LocalConnector(pub ThreadSafeDNSResolver);

impl Service<Uri> for LocalConnector {
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = AnyStream;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, remote: Uri) -> Self::Future {
        let host = remote
            .host()
            .unwrap_or_else(|| print_and_exit!("invalid url: {}", remote))
            .to_owned();

        let dns = self.0.clone();

        Box::pin(async move {
            let remote_ip = dns
                .resolve(host.as_str(), false)
                .await
                .map_err(std::io::Error::other)?
                .ok_or(std::io::Error::other("no dns result"))?;
            let remote_port =
                remote.port_u16().unwrap_or(match remote.scheme_str() {
                    None => 80,
                    Some(s) => match s {
                        "http" => 80,
                        "https" => 443,
                        _ => print_and_exit!("invalid url: {}", remote),
                    },
                });
            new_tcp_stream(
                (remote_ip, remote_port).into(),
                None,
                #[cfg(target_os = "linux")]
                None,
            )
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
    dns_resolver: ThreadSafeDNSResolver,
) -> std::io::Result<HttpClient> {
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(GLOBAL_ROOT_STORE.clone())
        .with_no_client_auth();
    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let connector = LocalConnector(dns_resolver);

    let connector: hyper_rustls::HttpsConnector<LocalConnector> =
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(connector);

    Ok(Client::builder(TokioExecutor::new()).build(connector))
}
