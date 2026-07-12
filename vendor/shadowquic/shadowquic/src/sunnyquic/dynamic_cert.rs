use arc_swap::ArcSwap;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::error::{SError, SResult};

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use rustls::crypto::ring::sign::any_supported_type;

#[cfg(feature = "aws-lc-rs")]
use rustls::crypto::aws_lc_rs::sign::any_supported_type;

#[derive(Clone, Debug)]
pub(crate) struct DynamicCertResolver {
    cert: Arc<ArcSwap<CertifiedKey>>,
}

impl DynamicCertResolver {
    pub fn new(key_path: &PathBuf, cert_path: &PathBuf) -> SResult<Self> {
        Ok(Self {
            cert: Arc::new(ArcSwap::new(
                Self::parse_key_and_cert(key_path, cert_path)?.into(),
            )),
        })
    }

    fn update_cert(&self, new_cert: CertifiedKey) {
        let cert = Arc::new(new_cert);
        self.cert.store(cert);
    }
    fn parse_key_and_cert(key_path: &PathBuf, cert_path: &PathBuf) -> Result<CertifiedKey, SError> {
        let cert_der: Vec<CertificateDer<'_>> = CertificateDer::pem_file_iter(cert_path)
            .map_err(|x| SError::RustlsError(x.to_string()))?
            .filter_map(|x| x.ok())
            .collect();
        let priv_key = PrivateKeyDer::from_pem_file(key_path)
            .map_err(|x| SError::RustlsError(x.to_string()))?;

        // Create CertifiedKey
        let key = any_supported_type(&priv_key)
            .map_err(|_| SError::RustlsError("invalid private key".to_string()))?;

        let certified_key = CertifiedKey::new(cert_der, key);
        Ok(certified_key)
    }

    pub async fn watch_cert_and_update(
        self,
        key_path: PathBuf,
        cert_path: PathBuf,
    ) -> Result<(), SError> {
        use notify::{Event, RecursiveMode, Watcher};
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                tx.blocking_send(event).unwrap();
            }
        })
        .expect("Failed to watch certificates and private key");

        watcher
            .watch(&cert_path, RecursiveMode::NonRecursive)
            .expect("Failed to watch certificates and private key");

        watcher
            .watch(&key_path, RecursiveMode::NonRecursive)
            .expect("Failed to watch certificates and private key");

        let mut last_reload = std::time::Instant::now()
            .checked_sub(Duration::from_secs(10))
            .unwrap_or(std::time::Instant::now());

        while let Some(event) = rx.recv().await {
            let mut reload = false;
            for path in event.paths {
                if let Some(name) = path.file_name()
                    && (Some(name) == cert_path.file_name() || Some(name) == key_path.file_name())
                {
                    reload = true;
                }
            }

            if reload {
                if last_reload.elapsed().as_secs() < 1 {
                    continue;
                }
                last_reload = std::time::Instant::now();
                tokio::time::sleep(Duration::from_millis(100)).await;

                let _ = Self::parse_key_and_cert(&key_path, &cert_path)
                    .map(|x| {
                        self.update_cert(x);
                    })
                    .map_err(|x| tracing::error!("failed to reload certificate: {}", x));
                tracing::info!("certificate reloaded");
            }
        }

        Ok(())
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let cert = self.cert.load();
        Some(cert.clone())
    }
}
