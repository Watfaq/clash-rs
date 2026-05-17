use async_trait::async_trait;
use serde::Serialize;
use std::{io, sync::Arc};

use super::Transport;
use crate::{
    common::{
        errors::map_io_error,
        tls::{DefaultTlsVerifier, GLOBAL_ROOT_STORE, load_client_cert_and_key},
    },
    proxy::AnyStream,
};

#[derive(Serialize, Clone, Default)]
pub struct TLSOptions {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls_key`.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls_cert`.
    pub tls_key: Option<String>,
}

impl TryFrom<TLSOptions> for Client {
    type Error = io::Error;

    fn try_from(opt: TLSOptions) -> Result<Self, Self::Error> {
        Client::new(
            opt.skip_cert_verify,
            opt.sni,
            opt.alpn,
            None,
            opt.tls_cert.as_deref(),
            opt.tls_key.as_deref(),
        )
    }
}

pub struct Client {
    pub sni: String,
    pub expected_alpn: Option<String>,
    /// Cached connector built once at construction time.
    /// Sharing this across connections enables TLS session resumption
    /// (both TLS 1.2 session IDs/tickets and TLS 1.3 PSK resumption),
    /// which saves a full round-trip on every subsequent connection to the
    /// same proxy server.
    connector: tokio_rustls::TlsConnector,
}

impl Client {
    /// Create a new TLS client.
    ///
    /// When `tls_cert` and `tls_key` are both `Some`, mutual TLS (mTLS) is
    /// enabled: the client will present the given certificate to the server.
    /// Both must be either `None` (no client auth) or `Some` (mTLS); mixing
    /// them returns an error.
    pub fn new(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> io::Result<Self> {
        let mut tls_config = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => {
                let (certs, private_key) = load_client_cert_and_key(cert, key)?;
                rustls::ClientConfig::builder()
                    .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                    .with_client_auth_cert(certs, private_key)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid mTLS client cert/key: {e}"),
                        )
                    })?
            }
            (None, None) => rustls::ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tls-cert and tls-key must both be set or both omitted",
                ));
            }
        };

        tls_config.alpn_protocols = alpn
            .unwrap_or_default()
            .into_iter()
            .map(|x| x.as_bytes().to_vec())
            .collect();

        tls_config.dangerous().set_certificate_verifier(Arc::new(
            DefaultTlsVerifier::new(None, skip_cert_verify),
        ));

        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

        Ok(Self {
            sni,
            expected_alpn,
            connector,
        })
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let dns_name =
            rustls::pki_types::ServerName::try_from(self.sni.as_str().to_owned())
                .map_err(map_io_error)?;

        let c = self
            .connector
            .connect(dns_name, stream)
            .await
            .and_then(|x| {
                if let Some(expected_alpn) = self.expected_alpn.as_ref()
                    && x.get_ref().1.alpn_protocol()
                        != Some(expected_alpn.as_bytes())
                {
                    return Err(io::Error::other(format!(
                        "unexpected alpn protocol: {:?}, expected: {:?}",
                        x.get_ref().1.alpn_protocol(),
                        expected_alpn
                    )));
                }

                Ok(x)
            });
        c.map(|x| Box::new(x) as _)
    }
}
