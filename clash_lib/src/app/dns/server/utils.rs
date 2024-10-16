use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{fs, path::Path};

use crate::common::errors::new_io_error;

use super::dummy_keys::{TEST_CERT, TEST_KEY};

pub fn load_cert_chain(
    cert_path: &Path,
) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let cert_chain = fs::read(cert_path)?;
    if cert_path.extension().map_or(false, |x| x == "der") {
        Ok(vec![CertificateDer::from(cert_chain)])
    } else {
        rustls_pemfile::certs(&mut &*cert_chain).collect::<Result<_, _>>()
    }
}

pub fn load_priv_key(key_path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    let key = fs::read(key_path)?;
    if key_path.extension().map_or(false, |x| x == "der") {
        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
    } else {
        rustls_pemfile::private_key(&mut &*key)?
            .ok_or(new_io_error("no private key found"))
    }
}

pub fn load_default_cert() -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut TEST_CERT.as_bytes())
        .collect::<Result<_, _>>()
        .unwrap()
}

pub fn load_default_key() -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut TEST_KEY.as_bytes())
        .unwrap()
        .unwrap()
}
