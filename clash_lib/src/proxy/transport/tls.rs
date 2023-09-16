use std::{io, sync::Arc};

use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use serde::Serialize;
use tokio_rustls::TlsConnector;
use tracing::warn;

use crate::{common::tls, proxy::AnyStream};

#[derive(Serialize, Clone)]
pub struct TLSOptions {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
}

pub async fn wrap_stream(stream: AnyStream, opt: TLSOptions) -> io::Result<AnyStream> {
    // TODO save root store to avoid re-creating it
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let mut tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
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

    let connector = TlsConnector::from(Arc::new(tls_config));
    let dns_name = ServerName::try_from(opt.sni.as_str())
        .expect(format!("invalid server name: {}", opt.sni).as_str());

    connector
        .connect(dns_name, stream)
        .await
        .map(|x| Box::new(x) as _)
}
