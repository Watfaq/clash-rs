use std::{
    collections::HashMap,
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
use tracing::{debug, error};

use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::tls::GLOBAL_ROOT_STORE,
    proxy::{AnyOutboundHandler, AnyStream, utils::new_tcp_stream},
    session::Session,
};

#[derive(Clone)]
/// A LocalConnector that is generalised to connect to any url
pub struct LocalConnector {
    pub dns_resolver: ThreadSafeDNSResolver,
    pub outbounds: Option<HashMap<String, AnyOutboundHandler>>,
}
impl LocalConnector {
    pub fn new(dns_resolver: ThreadSafeDNSResolver) -> Self {
        Self {
            dns_resolver,
            outbounds: None,
        }
    }

    pub fn with_outbounds(mut self, outbounds: Vec<AnyOutboundHandler>) -> Self {
        let mut obs = HashMap::new();
        for handler in outbounds {
            obs.insert(handler.name().to_owned(), handler);
        }
        self.outbounds = Some(obs);
        self
    }
}

impl Service<Uri> for LocalConnector {
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = AnyStream;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, remote: Uri) -> Self::Future {
        let host = if let Some(host) = remote.host() {
            host.to_owned()
        } else {
            return Box::pin(async move {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("uri must have a host: {remote}"),
                ))
            });
        };

        let dns = self.dns_resolver.clone();
        let outbounds = self.outbounds.clone();

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
                        _ => {
                            return Err(std::io::Error::other(format!(
                                "unsupported scheme: {s}"
                            )));
                        }
                    },
                });

            error!(
                url = ?remote.authority(),
                fragments = remote.to_string().rsplit_once('#')
                    .map(|(x, _)| x)
                    .unwrap_or(""),
                "connecting to remote"
            );
            if let Some(fragments) =
                remote.to_string().rsplit_once('#').map(|(_, x)| x)
            {
                let pairs = fragments.split('&').filter_map(|x| {
                    let mut kv = x.splitn(2, '=');
                    if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                        Some((k, v))
                    } else {
                        None
                    }
                });
                let mut params = HashMap::new();
                for (k, v) in pairs {
                    params.insert(k.to_owned(), v.to_owned());
                }
                if let Some(selected_outbound) = params.get("_clash_outbound") {
                    if let Some(outbounds) = outbounds {
                        debug!("using selected outbound: {selected_outbound}");
                        if let Some(handler) =
                            outbounds.get(selected_outbound.as_str())
                        {
                            let sess = Session {
                                network: crate::session::Network::Tcp,
                                typ: crate::session::Type::Ignore,
                                destination: crate::session::SocksAddr::Ip(
                                    (remote_ip, remote_port).into(),
                                ),
                                ..Default::default()
                            };
                            return handler
                                .connect_stream(&sess, dns)
                                .await
                                .map(|x| x as _);
                        }
                    }
                }
            }

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

/// Creates a new HTTP client with the given DNS resolver and optional bootstrap
/// outbounds, that is used by clash to send outgoing HTTP requests.
pub fn new_http_client(
    dns_resolver: ThreadSafeDNSResolver,
    bootstrap_outbounds: Option<Vec<AnyOutboundHandler>>,
) -> std::io::Result<HttpClient> {
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(GLOBAL_ROOT_STORE.clone())
        .with_no_client_auth();
    if std::env::var("SSLKEYLOGFILE").is_ok() {
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut connector = LocalConnector::new(dns_resolver);
    if let Some(outbounds) = bootstrap_outbounds {
        connector = connector.with_outbounds(outbounds);
    }

    let connector: hyper_rustls::HttpsConnector<LocalConnector> =
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(connector);

    Ok(Client::builder(TokioExecutor::new()).build(connector))
}
