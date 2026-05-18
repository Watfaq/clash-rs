//! TLS acceptor construction for the AnyTLS inbound listener.

use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

use crate::common::tls::load_cert_and_key;

/// Build a TLS acceptor from PEM certificate and private key.
/// Strings containing `-----BEGIN` are treated as inline PEM; otherwise
/// they are interpreted as file paths.
/// When both are `None`, an ephemeral self-signed certificate is generated.
pub(crate) fn build_tls_acceptor(
    certificate: Option<&str>,
    private_key: Option<&str>,
) -> std::io::Result<TlsAcceptor> {
    let (certs, key) = match (certificate, private_key) {
        (Some(cert), Some(key)) => load_cert_and_key(cert, key)?,
        (None, None) => {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "failed to generate ephemeral anytls certificate: {e}"
                        ))
                    })?;
            let cert_der =
                rustls::pki_types::CertificateDer::from(cert.der().to_vec());
            let key_der = rustls::pki_types::PrivateKeyDer::try_from(
                signing_key.serialize_der(),
            )
            .map_err(|e| {
                std::io::Error::other(format!(
                    "failed to serialize ephemeral anytls key: {e}"
                ))
            })?;
            (vec![cert_der], key_der)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "anytls inbound: certificate and private-key must both be set, or \
                 both omitted",
            ));
        }
    };

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("anytls TLS config error: {e}"),
            )
        })?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_crypto_provider() {
        crate::setup_default_crypto_provider();
    }

    #[test]
    fn test_build_tls_acceptor_with_inline_pem() {
        install_crypto_provider();
        let rcgen::CertifiedKey {
            cert,
            signing_key: key_pair,
        } = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen cert generation failed");
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let result = build_tls_acceptor(Some(&cert_pem), Some(&key_pem));
        assert!(
            result.is_ok(),
            "build_tls_acceptor must succeed with valid inline PEM: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_tls_acceptor_ephemeral_when_none() {
        install_crypto_provider();
        let result = build_tls_acceptor(None, None);
        assert!(
            result.is_ok(),
            "build_tls_acceptor must generate an ephemeral cert when both are \
             None: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_tls_acceptor_mismatched_args_fails() {
        install_crypto_provider();
        // One provided but not the other → error
        let result = build_tls_acceptor(Some("some-cert"), None);
        assert!(result.is_err(), "mismatched cert/key must fail");
    }

    #[test]
    fn test_build_tls_acceptor_invalid_cert_fails() {
        install_crypto_provider();
        let result = build_tls_acceptor(
            Some("-----BEGIN CERTIFICATE-----\nbaddata\n-----END CERTIFICATE-----"),
            Some("-----BEGIN PRIVATE KEY-----\nbaddata\n-----END PRIVATE KEY-----"),
        );
        assert!(
            result.is_err(),
            "build_tls_acceptor must fail with invalid PEM"
        );
    }
}
