use std::io;

use serde::Serialize;

use crate::proxy::AnyStream;

#[derive(Serialize, Clone)]
pub struct TLSOptions {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
}

pub async fn wrap_stream(
    stream: AnyStream,
    opt: TLSOptions,
    expected_alpn: Option<&str>,
) -> io::Result<AnyStream> {
    use std::sync::Arc;

    use crate::common::tls::{self, GLOBAL_ROOT_STORE};

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(GLOBAL_ROOT_STORE.clone())
        .with_no_client_auth();
    tls_config.alpn_protocols = opt
        .alpn
        .unwrap_or_default()
        .into_iter()
        .map(|x| x.as_bytes().to_vec())
        .collect();

    if opt.skip_cert_verify {
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));
    }

    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let dns_name =
        rustls::pki_types::ServerName::try_from(opt.sni.as_str().to_owned())
            .unwrap_or_else(|_| panic!("invalid server name: {}", opt.sni));

    let c = connector.connect(dns_name, stream).await.and_then(|x| {
        if let Some(expected_alpn) = expected_alpn {
            if x.get_ref().1.alpn_protocol() != Some(expected_alpn.as_bytes()) {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "unexpected alpn protocol: {:?}, expected: {:?}",
                        x.get_ref().1.alpn_protocol(),
                        expected_alpn
                    ),
                ));
            }
        }

        Ok(x)
    });
    c.map(|x| Box::new(x) as _)
}
