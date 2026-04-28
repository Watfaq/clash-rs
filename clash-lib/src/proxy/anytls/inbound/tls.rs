//! TLS acceptor construction for the AnyTLS inbound listener.

use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::warn;

/// Build a TLS acceptor from PEM certificate and private key.
/// Strings containing `-----BEGIN` are treated as inline PEM; otherwise
/// they are interpreted as file paths.
/// When both are `None`, an ephemeral self-signed certificate is generated.
pub(crate) fn build_tls_acceptor(
    certificate: Option<&str>,
    private_key: Option<&str>,
) -> std::io::Result<TlsAcceptor> {
    let (certs, key) = match (certificate, private_key) {
        (Some(cert), Some(key)) => {
            let cert_pem = if cert.contains("-----BEGIN") {
                cert.to_owned()
            } else {
                std::fs::read_to_string(cert).map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!("failed to read anytls certificate '{cert}': {e}"),
                    )
                })?
            };
            let key_pem = if key.contains("-----BEGIN") {
                key.to_owned()
            } else {
                std::fs::read_to_string(key).map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!("failed to read anytls private key '{key}': {e}"),
                    )
                })?
            };

            let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls_pemfile::certs(&mut cert_pem.as_bytes())
                    .filter_map(|r| {
                        r.map_err(|e| {
                            warn!("failed to parse anytls certificate: {e}")
                        })
                        .ok()
                    })
                    .collect();

            if certs.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "no valid certificates found in anytls certificate PEM",
                ));
            }

            let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("failed to parse anytls private key: {e}"),
                    )
                })?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "no private key found in anytls private key PEM",
                    )
                })?;

            (certs, key)
        }
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
        #[cfg(feature = "aws-lc-rs")]
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        let _ = rustls::crypto::ring::default_provider().install_default();
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
