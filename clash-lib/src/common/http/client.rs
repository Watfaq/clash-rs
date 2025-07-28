use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::tls::GLOBAL_ROOT_STORE,
    proxy::{self, AnyOutboundHandler},
    session::Session,
};
use futures::FutureExt;
use hyper_util::rt::TokioIo;
use std::{collections::HashMap, sync::Arc};
use tracing::{trace, warn};

#[derive(Clone, Debug)]
pub(crate) struct ClashHTTPClientExt {
    pub(crate) outbound: Option<String>,
}

/// A simple HTTP client that can be used to make HTTP requests.
/// Not performant for lack of connection pooling, but useful for simple tasks.
#[derive(Clone)]
pub struct HttpClient {
    dns_resolver: ThreadSafeDNSResolver,
    outbounds: Option<HashMap<String, AnyOutboundHandler>>,
    tls_config: Arc<rustls::ClientConfig>,
    timeout: tokio::time::Duration,
}

impl HttpClient {
    pub fn new(
        dns_resolver: ThreadSafeDNSResolver,
        bootstrap_outbounds: Option<Vec<AnyOutboundHandler>>,
        timeout: Option<tokio::time::Duration>,
    ) -> std::io::Result<HttpClient> {
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        Ok(HttpClient {
            dns_resolver,
            outbounds: bootstrap_outbounds.map(|obs| {
                let mut map = HashMap::new();
                for handler in obs {
                    map.insert(handler.name().to_owned(), handler);
                }
                map
            }),
            tls_config: Arc::new(tls_config),
            timeout: timeout.unwrap_or(tokio::time::Duration::from_secs(10)),
        })
    }

    pub async fn request<T>(
        &self,
        req: http::Request<T>,
    ) -> Result<http::Response<hyper::body::Incoming>, std::io::Error>
    where
        T: hyper::body::Body + Send + 'static,
        <T as hyper::body::Body>::Data: Send,
        <T as hyper::body::Body>::Error: std::error::Error + Send + Sync,
    {
        let uri = req.uri();
        let host = uri
            .host()
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("uri must have a host: {uri}"),
            ))?
            .to_owned();
        let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
            None => 80,
            Some(s) => match s {
                "http" => 80,
                "https" => 443,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unsupported scheme: {s}"),
                    ));
                }
            },
        });

        let req_ext = req.extensions().get::<ClashHTTPClientExt>();
        let outbound = req_ext
            .and_then(|ext| ext.outbound.clone())
            .as_ref()
            .and_then(|x| {
                self.outbounds
                    .as_ref()
                    .and_then(|outbounds| outbounds.get(x).cloned())
            })
            .unwrap_or(Arc::new(proxy::direct::Handler::new()) as _);

        trace!(outbound = %outbound.name(), "using outbound");
        let sess = Session {
            network: crate::session::Network::Tcp,
            typ: crate::session::Type::Ignore,
            destination: crate::session::SocksAddr::Domain(host.clone(), port),
            ..Default::default()
        };
        let stream = tokio::time::timeout(
            self.timeout,
            outbound.connect_stream(&sess, self.dns_resolver.clone()),
        )
        .await?
        .inspect_err(|e| {
            warn!(outbound = outbound.name(), err = ?e, "download via proxy");
        })?;

        let resp = match uri.scheme() {
            Some(scheme) if scheme == &http::uri::Scheme::HTTP => {
                let io = TokioIo::new(stream);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(std::io::Error::other)?;

                tokio::task::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("HTTP connection error: {}", err);
                    }
                });

                sender.send_request(req).boxed()
            }
            Some(scheme) if scheme == &http::uri::Scheme::HTTPS => {
                let connector =
                    tokio_rustls::TlsConnector::from(self.tls_config.clone());

                let stream = tokio::time::timeout(
                    self.timeout,
                    connector.connect(
                        host.try_into().expect("must be valid SNI"),
                        stream,
                    ),
                )
                .await??;

                let io = TokioIo::new(stream);

                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(std::io::Error::other)?;

                tokio::task::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("HTTP connection error: {}", err);
                    }
                });

                sender.send_request(req).boxed()
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid url: {uri}: unsupported scheme"),
                ));
            }
        };

        resp.await
            .map_err(|e| std::io::Error::other(format!("HTTP request failed: {e}")))
    }
}

/// Creates a new HTTP client with the given DNS resolver and optional bootstrap
/// outbounds, that is used by clash to send outgoing HTTP requests.
pub fn new_http_client(
    dns_resolver: ThreadSafeDNSResolver,
    bootstrap_outbounds: Option<Vec<AnyOutboundHandler>>,
) -> std::io::Result<HttpClient> {
    HttpClient::new(dns_resolver, bootstrap_outbounds, None)
}
