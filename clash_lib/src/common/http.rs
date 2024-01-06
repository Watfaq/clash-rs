use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::Future;

use hyper::{
    client::connect::{Connected, Connection},
    Uri,
};
use tower::Service;

use crate::{
    app::dns::ThreadSafeDNSResolver,
    proxy::{utils::new_tcp_stream, AnyStream},
};

#[derive(Clone)]
/// A LocalConnector that is generalised to connect to any url
pub struct LocalConnector(pub ThreadSafeDNSResolver);

impl Service<Uri> for LocalConnector {
    type Response = AnyStream;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, remote: Uri) -> Self::Future {
        let host = remote
            .host()
            .unwrap_or_else(|| panic!("invalid url: {}", remote))
            .to_owned();

        let dns = self.0.clone();

        Box::pin(async move {
            new_tcp_stream(
                dns,
                host.as_str(),
                remote.port_u16().unwrap_or(match remote.scheme_str() {
                    None => 80,
                    Some(s) => match s {
                        "http" => 80,
                        "https" => 443,
                        _ => panic!("invalid url: {}", remote),
                    },
                }),
                None,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                None,
            )
            .await
        })
    }
}

impl Connection for AnyStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

#[cfg(not(windows))]
pub type HttpClient = hyper::Client<hyper_boring::HttpsConnector<LocalConnector>>;
#[cfg(windows)]
pub type HttpClient = hyper::Client<hyper_rustls::HttpsConnector<LocalConnector>>;

#[cfg(not(windows))]
pub fn new_http_client(dns_resolver: ThreadSafeDNSResolver) -> std::io::Result<HttpClient> {
    use super::errors::map_io_error;
    use boring::ssl::{SslConnector, SslMethod};

    let connector = LocalConnector(dns_resolver);

    let mut ssl = SslConnector::builder(SslMethod::tls()).map_err(map_io_error)?;
    ssl.set_alpn_protos(b"\x02h2\x08http/1.1")
        .map_err(map_io_error)?;

    let connector =
        hyper_boring::HttpsConnector::with_connector(connector, ssl).map_err(map_io_error)?;
    Ok(hyper::Client::builder().build::<_, hyper::Body>(connector))
}

#[cfg(windows)]
pub fn new_http_client(dns_resolver: ThreadSafeDNSResolver) -> std::io::Result<HttpClient> {
    use std::sync::Arc;

    use super::tls::GLOBAL_ROOT_STORE;

    let connector = LocalConnector(dns_resolver);

    let mut tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(GLOBAL_ROOT_STORE.clone())
        .with_no_client_auth();
    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(connector);

    Ok(hyper::Client::builder().build::<_, hyper::Body>(connector))
}
