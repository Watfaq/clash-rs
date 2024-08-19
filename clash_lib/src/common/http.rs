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
            .unwrap_or_else(|| panic!("invalid url: {}", remote))
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
                        _ => panic!("invalid url: {}", remote),
                    },
                });
            new_tcp_stream(
                (remote_ip, remote_port).into(),
                None,
                #[cfg(any(target_os = "linux", target_os = "android"))]
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

pub type HttpClient = hyper::Client<hyper_rustls::HttpsConnector<LocalConnector>>;

pub fn new_http_client(
    dns_resolver: ThreadSafeDNSResolver,
) -> std::io::Result<HttpClient> {
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
