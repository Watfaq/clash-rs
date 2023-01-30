use crate::common::new_error;
use boring::x509::X509;
use std::io;

static PKIX_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

fn usable_for_rustls(uses: schannel::cert_context::ValidUses) -> bool {
    match uses {
        schannel::cert_context::ValidUses::All => true,
        schannel::cert_context::ValidUses::Oids(strs) => strs.iter().any(|x| x == PKIX_SERVER_AUTH),
    }
}

// Adapted from https://github.com/rustls/rustls-native-certs
pub fn load_native_certs() -> io::Result<Vec<X509>> {
    let mut certs = Vec::new();

    let current_user_store = schannel::cert_store::CertStore::open_current_user("Root")?;

    for cert in current_user_store.certs() {
        if usable_for_rustls(cert.valid_uses().unwrap()) && cert.is_time_valid().unwrap() {
            certs.push(X509::from_der(cert.to_der()).map_err(new_error)?);
        }
    }
    Ok(certs)
}
