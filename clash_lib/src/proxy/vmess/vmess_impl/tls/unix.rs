use crate::common::new_error;
use boring::x509::X509;
use std::io;

// Adapted from https://github.com/rustls/rustls-native-certs
pub fn load_native_certs() -> io::Result<Vec<X509>> {
    let likely_locations = openssl_probe::probe();

    match likely_locations.cert_file {
        Some(cert_file) => {
            let pem = std::fs::read(cert_file)?;
            X509::stack_from_pem(pem.as_ref()).map_err(new_error)
        }
        None => Ok(Vec::new()),
    }
}
