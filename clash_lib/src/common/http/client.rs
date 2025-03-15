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
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use tokio::net::TcpStream;
use tower::Service;

use crate::{
    app::dns::ThreadSafeDNSResolver, common::tls::GLOBAL_ROOT_STORE, print_and_exit,
    proxy::utils::new_tcp_stream,
};

#[derive(Clone)]
/// A LocalConnector that is generalised to connect to any url
pub struct LocalConnector(pub ThreadSafeDNSResolver);

impl Service<Uri> for LocalConnector {
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = TokioIo<TcpStream>;

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
                .map_err(|v| std::io::Error::new(std::io::ErrorKind::Other, v))?
                .ok_or(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "no dns result",
                ))?;
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
            .map(|x| TokioIo::new(x))
        })
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
