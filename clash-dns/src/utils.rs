use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{fs, path::Path};

use super::dummy_keys::{TEST_CERT, TEST_KEY};

use std::io;

pub fn new_io_error<T>(msg: T) -> io::Error
where
    T: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, msg.into())
}

pub fn load_cert_chain(
    cert_path: &Path,
) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let cert_chain = fs::read(cert_path).map_err(|e| {
        new_io_error(format!(
            "failed to read certificate file {}: {}",
            cert_path.display(),
            e
        ))
    })?;
    if cert_path.extension().is_some_and(|x| x == "der") {
        Ok(vec![CertificateDer::from(cert_chain)])
    } else {
        rustls_pemfile::certs(&mut &*cert_chain).collect::<Result<_, _>>()
    }
}

pub fn load_priv_key(key_path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    let key = fs::read(key_path).map_err(|e| {
        new_io_error(format!(
            "failed to read private key file {}: {}",
            key_path.display(),
            e
        ))
    })?;
    if key_path.extension().is_some_and(|x| x == "der") {
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
