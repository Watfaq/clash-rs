use std::{io, sync::Arc};

use rustls::{ClientConfig, ServerName};
use serde::Serialize;
use tokio_rustls::TlsConnector;

use crate::{
    common::tls::{self, GLOBAL_ROOT_STORE},
    proxy::AnyStream,
};

#[derive(Serialize, Clone)]
pub struct TLSOptions {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
}

pub async fn wrap_stream(stream: AnyStream, opt: TLSOptions) -> io::Result<AnyStream> {
    let mut tls_config = ClientConfig::builder()
        .with_safe_defaults()
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
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier {}));
    }

    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let connector = TlsConnector::from(Arc::new(tls_config));
    let dns_name = ServerName::try_from(opt.sni.as_str())
        .expect(format!("invalid server name: {}", opt.sni).as_str());

    connector
        .connect(dns_name, stream)
        .await
        .map(|x| Box::new(x) as _)
}
