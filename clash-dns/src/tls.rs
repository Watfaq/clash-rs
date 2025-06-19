use std::sync::{Arc, OnceLock};

use rustls::{
    RootCertStore,
    client::WebPkiServerVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
};

static GLOBAL_ROOT_STORE: OnceLock<Arc<RootCertStore>> = OnceLock::new();

pub fn global_root_store() -> Arc<RootCertStore> {
    GLOBAL_ROOT_STORE
        .get_or_init(|| {
            let root_store =
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
            Arc::new(root_store)
        })
        .clone()
}

#[derive(Debug)]
pub struct DummyTlsVerifier(Arc<WebPkiServerVerifier>);

impl DummyTlsVerifier {
    pub fn new() -> Self {
        Self(
            WebPkiServerVerifier::builder(global_root_store().clone())
                .build()
                .unwrap(),
        )
    }
}

impl rustls::client::danger::ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
