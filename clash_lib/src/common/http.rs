use std::{
    pin::Pin,
    task::{Context, Poll},
};

use boring::ssl::{SslConnector, SslMethod};
use futures::Future;
use http::Uri;
use hyper::client::connect::{Connected, Connection};
use hyper_boring::HttpsConnector;
use tower::Service;

use crate::{
    app::ThreadSafeDNSResolver,
    proxy::{utils::new_tcp_stream, AnyStream},
};

use super::errors::map_io_error;

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
            .expect(format!("invalid url: {}", remote.to_string()).as_str())
            .to_owned();

        let dns = self.0.clone();

        Box::pin(async move {
            new_tcp_stream(
                dns,
                host.as_str(),
                remote.port_u16().unwrap_or(match remote.scheme_str() {
                    None => 80,
                    Some(s) => match s {
                        s if s == "http" => 80,
                        s if s == "https" => 443,
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

pub type HttpClient = hyper::Client<HttpsConnector<LocalConnector>>;

pub fn new_http_client(dns_resolver: ThreadSafeDNSResolver) -> std::io::Result<HttpClient> {
    let connector = LocalConnector(dns_resolver);

    let mut ssl = SslConnector::builder(SslMethod::tls()).map_err(map_io_error)?;
    ssl.set_alpn_protos(b"\x02h2\x08http/1.1")
        .map_err(map_io_error)?;

    let connector = HttpsConnector::with_connector(connector, ssl).map_err(map_io_error)?;
    Ok(hyper::Client::builder().build::<_, hyper::Body>(connector))
}
