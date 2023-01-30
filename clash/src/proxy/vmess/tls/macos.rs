use boring::x509::X509;
use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};
use std::io;

use std::collections::HashMap;
use std::io::{Error, ErrorKind};

use crate::common::errors::map_io_error;

// Adapted from https://github.com/rustls/rustls-native-certs
pub fn load_native_certs() -> io::Result<Vec<X509>> {
    // The various domains are designed to interact like this:
    //
    // "Per-user Trust Settings override locally administered
    //  Trust Settings, which in turn override the System Trust
    //  Settings."
    //
    // So we collect the certificates in this order; as a map of
    // their DER encoding to what we'll do with them.  We don't
    // overwrite existing elements, which mean User settings
    // trump Admin trump System, as desired.

    let mut all_certs = HashMap::new();

    for domain in &[Domain::User, Domain::Admin, Domain::System] {
        let ts = TrustSettings::new(*domain);
        let iter = ts.iter().map_err(map_io_error)?;

        for cert in iter {
            let der = cert.to_der();

            // If there are no specific trust settings, the default
            // is to trust the certificate as a root cert.  Weird API but OK.
            // The docs say:
            //
            // "Note that an empty Trust Settings array means "always trust this cert,
            //  with a resulting kSecTrustSettingsResult of kSecTrustSettingsResultTrustRoot".
            let trusted = ts
                .tls_trust_settings_for_certificate(&cert)
                .map_err(|err| Error::new(ErrorKind::Other, err))?
                .unwrap_or(TrustSettingsForCertificate::TrustRoot);

            all_certs.entry(der).or_insert(trusted);
        }
    }

    let mut certs = Vec::new();

    // Now we have all the certificates and an idea of whether
    // to use them.
    for (der, trusted) in all_certs.drain() {
        use TrustSettingsForCertificate::*;
        if let TrustRoot | TrustAsRoot = trusted {
            certs.push(X509::from_der(&der).map_err(map_io_error)?);
        }
    }

    Ok(certs)
}
