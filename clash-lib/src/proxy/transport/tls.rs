use async_trait::async_trait;
use serde::Serialize;
use std::{io, sync::Arc};

use super::Transport;
use crate::{
    common::{
        errors::map_io_error,
        tls::{DefaultTlsVerifier, GLOBAL_ROOT_STORE},
    },
    proxy::AnyStream,
};

#[derive(Serialize, Clone)]
pub struct TLSOptions {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
}

impl From<TLSOptions> for Client {
    fn from(opt: TLSOptions) -> Self {
        Self::new(opt.skip_cert_verify, opt.sni, opt.alpn, None)
    }
}

pub struct Client {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    pub expected_alpn: Option<String>,
}

impl Client {
    pub fn new(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
    ) -> Self {
        Self {
            skip_cert_verify,
            sni,
            alpn,
            expected_alpn,
        }
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = self
            .alpn
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|x| x.as_bytes().to_vec())
            .collect();

        tls_config.dangerous().set_certificate_verifier(Arc::new(
            DefaultTlsVerifier::new(None, self.skip_cert_verify),
        ));

        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let dns_name =
            rustls::pki_types::ServerName::try_from(self.sni.as_str().to_owned())
                .map_err(map_io_error)?;

        let c = connector.connect(dns_name, stream).await.and_then(|x| {
            if let Some(expected_alpn) = self.expected_alpn.as_ref()
                && x.get_ref().1.alpn_protocol() != Some(expected_alpn.as_bytes())
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
