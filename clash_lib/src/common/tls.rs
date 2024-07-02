use once_cell::sync::Lazy;
use rustls::{
    client::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        WebPkiVerifier,
    },
    DigitallySignedStruct, OwnedTrustAnchor, RootCertStore,
};
use tracing::warn;

use rustls::{Certificate, ServerName};
use std::{sync::Arc, time::SystemTime};

pub static GLOBAL_ROOT_STORE: Lazy<Arc<RootCertStore>> =
    Lazy::new(global_root_store);

fn global_root_store() -> Arc<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    Arc::new(root_store)
}

/// Warning: NO validation on certs.
pub struct DummyTlsVerifier;

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
}

pub struct NoHostnameTlsVerifier;

impl ServerCertVerifier for NoHostnameTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verifier =
            WebPkiVerifier::new(rustls::RootCertStore { roots: vec![] }, None);
        match verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now,
        ) {
            Err(rustls::Error::UnsupportedNameType) => {
                warn!(
                    "skipping TLS cert name verification for server name: {:?}",
                    server_name
                );
                Ok(ServerCertVerified::assertion())
            }
            other => other,
        }
    }
}
