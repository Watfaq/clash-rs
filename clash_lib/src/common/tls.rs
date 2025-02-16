use once_cell::sync::Lazy;
use rustls::{
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    RootCertStore,
};
use tracing::warn;

use std::sync::Arc;

pub static GLOBAL_ROOT_STORE: Lazy<Arc<RootCertStore>> =
    Lazy::new(global_root_store);

fn global_root_store() -> Arc<RootCertStore> {
    let root_store = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    Arc::new(root_store)
}

/// Warning: NO validation on certs.
#[derive(Debug)]
pub struct DummyTlsVerifier(Arc<WebPkiServerVerifier>);

impl DummyTlsVerifier {
    pub fn new() -> Self {
        Self(
            WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
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

#[derive(Debug)]
pub struct SkipVerifier {
    fingerprint: Option<String>,
    skip: bool,
    pki: Arc<WebPkiServerVerifier>,
}

impl SkipVerifier {
    pub fn new(fingerprint: Option<String>, skip: bool) -> Self {
        Self {
            fingerprint,
            skip,
            pki: WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
                .build()
                .unwrap(),
        }
    }
}

impl ServerCertVerifier for SkipVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(ref fingerprint) = self.fingerprint {
            let cert_hex =
                super::utils::encode_hex(&super::utils::sha256(end_entity.as_ref()));
            if &cert_hex != fingerprint {
                return Err(rustls::Error::General(format!(
                    "cert hash mismatch: found: {}\nexcept: {}",
                    cert_hex, fingerprint
                )));
            }
        }

        if self.skip {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        self.pki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.pki.supported_verify_schemes()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.pki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.pki.verify_tls13_signature(message, cert, dss)
    }
}

#[derive(Debug)]
pub struct NoHostnameTlsVerifier(Arc<WebPkiServerVerifier>);

impl NoHostnameTlsVerifier {
    pub fn new() -> Self {
        Self(
            WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
                .build()
                .unwrap(),
        )
    }
}

impl ServerCertVerifier for NoHostnameTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self.0.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(rustls::Error::UnsupportedNameType) => {
                warn!(
                    "skipping TLS cert name verification for server name: {:?}",
                    server_name
                );
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
