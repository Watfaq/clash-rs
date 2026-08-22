//! What `client-fingerprint` in a proxy config actually does.
//!
//! Reality rests on one assumption: the ClientHello is indistinguishable from
//! a browser's. rustls sends the hello rustls needs, which is recognisably
//! rustls - no GREASE, no `signed_certificate_timestamp`, no ALPS, and a
//! cipher list that is exactly the set rustls can negotiate. Any one of those
//! separates it from a browser before a byte of application data moves.
//!
//! The mechanism lives in rustls (`ClientHelloProfile`). What lives here is
//! the browser table: which suites, which groups, which extensions, in what
//! order. The numbers below are taken from
//! [uTLS](https://github.com/refraction-networking/utls), which is the
//! reference every other implementation checks itself against.

use std::{str::FromStr, sync::Arc};

use rustls::{
    RawExtension, SignatureScheme,
    client::{ClientHelloProfile, EchMode},
    crypto::{CryptoProvider, SupportedKxGroup},
};
use tracing::warn;

/// Which client the ClientHello should be shaped like.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum ClientFingerprint {
    /// Chrome, and everything else built on Chromium.
    Chrome,

    /// No particular client: rustls own hello, with GREASE.
    ///
    /// Not a disguise. It is what is left when a browser profile was asked
    /// for and none is available, and it is still better than a hello with no
    /// GREASE at all, which is a signal in itself.
    Randomized,
}

/// Chrome 133, cipher suites in order, GREASE excluded.
///
/// The last six are static RSA and CBC key exchange, which rustls does not
/// implement and will never negotiate. They are here to be counted: fifteen
/// suites in this order is the first half of Chrome's fingerprint, and a list
/// trimmed to what rustls supports gives the game away on its own.
const CHROME_CIPHER_SUITES: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
];

/// Chrome 133, supported groups in order.
///
/// rustls derives the key shares from this: with X25519MLKEM768 first it
/// offers that plus its X25519 component, which is the pair Chrome sends.
const CHROME_NAMED_GROUPS: &[rustls::NamedGroup] = &[
    rustls::NamedGroup::X25519MLKEM768,
    rustls::NamedGroup::X25519,
    rustls::NamedGroup::secp256r1,
    rustls::NamedGroup::secp384r1,
];

/// Chrome 133, signature algorithms in order.
///
/// Shorter than rustls own list and in a different order, and both halves of
/// that matter: the list goes out in the hello, and the hello is what is being
/// matched. Nothing Chrome refuses to verify is accepted here either.
const CHROME_SIGNATURE_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
];

const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
/// `application_settings`, the codepoint Chrome 133 uses. Chrome 131 and
/// earlier sent 0x4469 for the same thing.
const EXT_APPLICATION_SETTINGS: u16 = 0x44cd;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// A `client-fingerprint` value naming a profile that is not implemented.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownFingerprint;

impl FromStr for ClientFingerprint {
    type Err = UnknownFingerprint;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            // All Chromium underneath, all sending Chrome's hello. 360 and QQ
            // are the Chinese Chromium forks Clash.Meta names.
            "chrome" | "edge" | "android" | "360" | "qq" => Ok(Self::Chrome),
            "random" | "randomized" => Ok(Self::Randomized),
            _ => Err(UnknownFingerprint),
        }
    }
}

/// Read a `client-fingerprint` value, falling back rather than pretending.
///
/// Firefox and Safari are real profiles that simply are not modelled here.
/// Quietly substituting Chrome for them would be worse than saying so: a
/// config asking for Firefox and getting Chrome is a mismatch nobody would
/// think to look for.
pub fn parse_client_fingerprint(value: &str, proxy: &str) -> ClientFingerprint {
    ClientFingerprint::from_str(value).unwrap_or_else(|_| {
        warn!(
            "client-fingerprint {value:?} is not implemented, {proxy} will use a \
             randomised fingerprint instead"
        );
        ClientFingerprint::Randomized
    })
}

impl ClientFingerprint {
    /// How the hello should be shaped.
    pub fn client_hello_profile(&self) -> ClientHelloProfile {
        match self {
            Self::Chrome => ClientHelloProfile {
                grease: true,
                cipher_suites: Some(CHROME_CIPHER_SUITES.to_vec()),
                append_extensions: vec![
                    // rustls signals "no renegotiation" with the SCSV in the
                    // cipher list; browsers use this extension. Since the
                    // suite list above is final, the SCSV is gone and this
                    // takes its place.
                    RawExtension {
                        typ: EXT_RENEGOTIATION_INFO,
                        payload: vec![0x00],
                    },
                    RawExtension::empty(EXT_SIGNED_CERTIFICATE_TIMESTAMP),
                    RawExtension {
                        typ: EXT_APPLICATION_SETTINGS,
                        payload: alpn_list(&["h2"]),
                    },
                ],
                // Chrome 131 dropped the padding extension: with GREASE ECH
                // the hello no longer lands in the range padding existed for.
                padding: None,
                ..Default::default()
            },
            Self::Randomized => ClientHelloProfile {
                grease: true,
                ..Default::default()
            },
        }
    }

    /// The GREASE ECH placeholder this profile sends, if it sends one.
    ///
    /// Chrome has carried an encrypted_client_hello extension full of random
    /// data since it started GREASEing ECH, and its absence is as visible as
    /// any other missing extension. It negotiates nothing: the payload is
    /// noise and the server ignores it.
    ///
    /// `None` without the `aws-lc-rs` feature - that is the only provider
    /// rustls ships HPKE for, and there is nothing to build the placeholder
    /// with otherwise.
    pub fn ech_mode(&self) -> Option<EchMode> {
        if !matches!(self, Self::Chrome) {
            return None;
        }

        #[cfg(feature = "aws-lc-rs")]
        {
            use rustls::{
                client::EchGreaseConfig,
                crypto::{
                    aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128, hpke::Hpke,
                },
            };

            // X25519 because that is what browsers GREASE with, and the KEM
            // decides the length of the encapsulated key on the wire.
            let suite = DH_KEM_X25519_HKDF_SHA256_AES_128 as &'static dyn Hpke;
            match suite.generate_key_pair() {
                Ok((public_key, _)) => {
                    Some(EchMode::Grease(EchGreaseConfig::new(suite, public_key)))
                }
                Err(e) => {
                    warn!("could not build a GREASE ECH placeholder: {e}");
                    None
                }
            }
        }

        #[cfg(not(feature = "aws-lc-rs"))]
        {
            None
        }
    }

    /// Signature algorithms to advertise, if this profile pins them.
    pub fn signature_schemes(&self) -> Option<&'static [SignatureScheme]> {
        match self {
            Self::Chrome => Some(CHROME_SIGNATURE_SCHEMES),
            Self::Randomized => None,
        }
    }

    /// ALPN protocols the browser offers.
    ///
    /// Callers that have their own ALPN requirement - a transport that must
    /// negotiate h2, say - keep theirs. This is for the ones that would
    /// otherwise send nothing, which is itself unlike any browser.
    pub fn alpn(&self) -> Option<Vec<Vec<u8>>> {
        match self {
            Self::Chrome => Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            Self::Randomized => None,
        }
    }

    /// The provider to build the config with: same primitives, browser order.
    ///
    /// Groups the provider does not have are skipped rather than faked. A key
    /// share for a group we cannot compute would fail the handshake, which is
    /// a worse outcome than one group out of place.
    pub fn crypto_provider(&self, base: Arc<CryptoProvider>) -> Arc<CryptoProvider> {
        let wanted = match self {
            Self::Chrome => CHROME_NAMED_GROUPS,
            Self::Randomized => return base,
        };

        let kx_groups: Vec<&'static dyn SupportedKxGroup> = wanted
            .iter()
            .filter_map(|group| {
                base.kx_groups
                    .iter()
                    .find(|supported| supported.name() == *group)
                    .copied()
            })
            .collect();

        if kx_groups.is_empty() {
            warn!(
                "none of the key exchange groups this fingerprint expects are \
                 available; leaving the provider alone"
            );
            return base;
        }

        for group in wanted {
            if !kx_groups.iter().any(|supported| supported.name() == *group) {
                warn!(
                    "key exchange group {group:?} is unavailable, dropped from the \
                     hello"
                );
            }
        }

        Arc::new(CryptoProvider {
            kx_groups,
            ..(*base).clone()
        })
    }
}

/// Encode an `ALPNProtocolList`: a u16 total length, then each protocol
/// prefixed with its own length byte.
///
/// Used for `application_settings`, whose body is the same shape as ALPN.
fn alpn_list(protocols: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    for protocol in protocols {
        body.push(protocol.len() as u8);
        body.extend_from_slice(protocol.as_bytes());
    }

    let mut out = (body.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_forks_all_get_chromes_hello() {
        for name in [
            "chrome", "Chrome", " CHROME ", "edge", "android", "360", "qq",
        ] {
            assert_eq!(
                ClientFingerprint::from_str(name),
                Ok(ClientFingerprint::Chrome),
                "{name}"
            );
        }
    }

    #[test]
    fn a_profile_we_do_not_have_falls_back_rather_than_lying() {
        for name in ["firefox", "safari", "ios", "nonsense"] {
            assert_eq!(ClientFingerprint::from_str(name), Err(UnknownFingerprint));
            // Randomised, not Chrome: a config asking for Firefox and silently
            // getting Chrome's hello is a mismatch nobody would look for.
            assert_eq!(
                parse_client_fingerprint(name, "test-proxy"),
                ClientFingerprint::Randomized,
                "{name}"
            );
        }
    }

    #[test]
    fn chrome_offers_fifteen_suites() {
        // The count is the first thing a JA4 fingerprint records. Fifteen is
        // Chrome; anything else is not, however good the rest looks.
        assert_eq!(CHROME_CIPHER_SUITES.len(), 15);
    }

    #[test]
    fn chrome_carries_the_extensions_rustls_does_not_model() {
        let profile = ClientFingerprint::Chrome.client_hello_profile();
        let types: Vec<u16> = profile
            .append_extensions
            .iter()
            .map(|ext| ext.typ)
            .collect();

        assert!(types.contains(&EXT_RENEGOTIATION_INFO));
        assert!(types.contains(&EXT_SIGNED_CERTIFICATE_TIMESTAMP));
        assert!(types.contains(&EXT_APPLICATION_SETTINGS));
    }

    #[test]
    fn renegotiation_info_replaces_the_scsv_that_the_suite_list_drops() {
        let profile = ClientFingerprint::Chrome.client_hello_profile();

        // Pinning the suite list removes TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        // which is how rustls says it will not renegotiate. Something has to
        // say it, or the peer is entitled to assume otherwise.
        assert!(
            !CHROME_CIPHER_SUITES.contains(&0x00ff),
            "the SCSV is not part of any browser's list"
        );
        let renegotiation = profile
            .append_extensions
            .iter()
            .find(|ext| ext.typ == EXT_RENEGOTIATION_INFO)
            .expect("no renegotiation_info");
        assert_eq!(renegotiation.payload, vec![0x00]);
    }

    #[test]
    fn alps_body_is_an_alpn_list() {
        // 00 03 - two bytes of list length
        //    02 - one byte of protocol length
        // 68 32 - "h2"
        assert_eq!(alpn_list(&["h2"]), vec![0x00, 0x03, 0x02, 0x68, 0x32]);
        assert_eq!(
            alpn_list(&["h2", "http/1.1"]),
            vec![
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f,
                0x31, 0x2e, 0x31,
            ]
        );
    }

    #[test]
    fn chrome_does_not_pad() {
        // Chrome 131 dropped the padding extension. Sending it would be as
        // visible as omitting it was before that.
        assert!(
            ClientFingerprint::Chrome
                .client_hello_profile()
                .padding
                .is_none()
        );
    }

    #[test]
    fn randomized_greases_and_leaves_everything_else_alone() {
        let profile = ClientFingerprint::Randomized.client_hello_profile();

        assert!(profile.grease);
        assert!(profile.cipher_suites.is_none());
        assert!(profile.append_extensions.is_empty());
        assert!(profile.prepend_extensions.is_empty());
        assert!(ClientFingerprint::Randomized.signature_schemes().is_none());
    }
}

/// Wraps a certificate verifier and pins the signature algorithms it offers.
///
/// The list goes out in the hello, so a browser profile that leaves rustls own
/// list in place is only half a disguise. Pinning it also narrows what will be
/// accepted, which is the same trade the browser makes.
#[derive(Debug)]
pub struct PinnedSchemeVerifier {
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    schemes: Vec<SignatureScheme>,
}

impl PinnedSchemeVerifier {
    /// Take the wanted schemes in the wanted order, keeping only the ones the
    /// wrapped verifier can actually check.
    ///
    /// Advertising a scheme we cannot verify would invite the server to sign
    /// with it and fail the handshake after the fact.
    pub fn new(
        inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
        wanted: &[SignatureScheme],
    ) -> Self {
        let available = inner.supported_verify_schemes();
        let schemes: Vec<SignatureScheme> = wanted
            .iter()
            .filter(|scheme| available.contains(scheme))
            .copied()
            .collect();

        Self { inner, schemes }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedSchemeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// What the shaped hello actually looks like on the wire.
///
/// The tests above check the browser table; these check that the table
/// survives the trip through rustls and comes out as bytes. A profile that is
/// correct in a struct and lost on the way to the socket would pass every
/// other test here.
#[cfg(test)]
mod wire {
    use super::*;
    use crate::common::tls::{DefaultTlsVerifier, build_tls_client_config};

    struct Hello {
        cipher_suites: Vec<u16>,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    impl Hello {
        fn types(&self) -> Vec<u16> {
            self.extensions.iter().map(|(typ, _)| *typ).collect()
        }

        fn body(&self, typ: u16) -> Option<&[u8]> {
            self.extensions
                .iter()
                .find(|(t, _)| *t == typ)
                .map(|(_, body)| body.as_slice())
        }

        /// supported_groups(10) and supported_versions(43) differ only in the
        /// width of their length prefix.
        fn u16_list(&self, typ: u16, prefix: usize) -> Vec<u16> {
            let body = self
                .body(typ)
                .unwrap_or_else(|| panic!("extension {typ:#06x} missing"));
            body[prefix..]
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect()
        }
    }

    fn is_grease(value: u16) -> bool {
        let [high, low] = value.to_be_bytes();
        high == low && low & 0x0f == 0x0a
    }

    fn capture(fingerprint: Option<ClientFingerprint>) -> Hello {
        #[cfg(feature = "aws-lc-rs")]
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
        let _ = rustls::crypto::ring::default_provider().install_default();

        let verifier = Arc::new(DefaultTlsVerifier::new(None, true));
        let config =
            build_tls_client_config(verifier, None, None, fingerprint).unwrap();

        let mut conn = rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from("www.example.com").unwrap(),
        )
        .unwrap();

        let mut record = Vec::new();
        conn.write_tls(&mut record).unwrap();
        parse(&record)
    }

    fn parse(record: &[u8]) -> Hello {
        let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        let handshake = &record[5..5 + record_len];
        assert_eq!(handshake[0], 0x01, "not a ClientHello");

        let len = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]])
            as usize;
        let body = &handshake[4..4 + len];

        let mut at = 2 + 32; // legacy_version, random
        at += 1 + body[at] as usize; // legacy_session_id

        let suites_len = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
        at += 2;
        let cipher_suites = body[at..at + suites_len]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        at += suites_len;

        at += 1 + body[at] as usize; // legacy_compression_methods

        let exts_len = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
        at += 2;
        let end = at + exts_len;

        let mut extensions = Vec::new();
        while at < end {
            let typ = u16::from_be_bytes([body[at], body[at + 1]]);
            let size = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            at += 4;
            extensions.push((typ, body[at..at + size].to_vec()));
            at += size;
        }
        assert_eq!(at, end, "extension list length disagrees with contents");

        Hello {
            cipher_suites,
            extensions,
        }
    }

    #[test]
    fn chrome_sends_chromes_cipher_list() {
        let hello = capture(Some(ClientFingerprint::Chrome));

        assert!(is_grease(hello.cipher_suites[0]));
        assert_eq!(&hello.cipher_suites[1..], CHROME_CIPHER_SUITES);

        // Sixteen with GREASE, fifteen without: the count is the first thing a
        // JA4 fingerprint records.
        assert_eq!(hello.cipher_suites.len(), 16);
    }

    #[test]
    fn chrome_carries_the_extensions_rustls_would_have_left_out() {
        let hello = capture(Some(ClientFingerprint::Chrome));
        let types = hello.types();

        assert!(
            types.contains(&EXT_SIGNED_CERTIFICATE_TIMESTAMP),
            "{types:04x?}"
        );
        assert!(types.contains(&EXT_APPLICATION_SETTINGS), "{types:04x?}");
        assert!(types.contains(&EXT_RENEGOTIATION_INFO), "{types:04x?}");

        assert_eq!(hello.body(EXT_SIGNED_CERTIFICATE_TIMESTAMP), Some(&[][..]));
        assert_eq!(
            hello.body(EXT_APPLICATION_SETTINGS),
            Some(&[0x00, 0x03, 0x02, b'h', b'2'][..])
        );
    }

    #[test]
    fn chrome_greases_the_lists_it_should() {
        let hello = capture(Some(ClientFingerprint::Chrome));

        // supported_groups: u16 list length, then the groups.
        assert!(is_grease(hello.u16_list(0x000a, 2)[0]));
        // supported_versions: u8 list length, then the versions.
        assert!(is_grease(hello.u16_list(0x002b, 1)[0]));

        let types = hello.types();
        let grease: Vec<u16> = types
            .iter()
            .copied()
            .filter(|typ| is_grease(*typ))
            .collect();
        assert_eq!(grease.len(), 2, "{types:04x?}");
    }

    #[test]
    fn chrome_offers_the_two_key_shares_chrome_offers() {
        let hello = capture(Some(ClientFingerprint::Chrome));

        // key_share(51): u16 list length, then entries of group, u16 length,
        // body. Chrome sends GREASE, X25519MLKEM768 and its X25519 component;
        // rustls derives the pair from the group order on its own.
        let body = hello.body(0x0033).expect("no key_share");
        let mut at = 2;
        let mut groups = Vec::new();
        while at < body.len() {
            groups.push(u16::from_be_bytes([body[at], body[at + 1]]));
            let size = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            at += 4 + size;
        }

        assert!(is_grease(groups[0]), "{groups:04x?}");
        assert_eq!(groups.len(), 3, "{groups:04x?}");
    }

    #[test]
    fn chrome_offers_brotli_certificate_compression() {
        let hello = capture(Some(ClientFingerprint::Chrome));

        // compress_certificate(27): a u8 list length, then u16 algorithm ids.
        // Brotli is 2, and it is the only one Chrome offers. Without it the
        // extension is absent entirely, and the extension set is exactly what
        // the common fingerprints hash.
        assert_eq!(hello.body(0x001b), Some(&[0x02, 0x00, 0x02][..]));
    }

    #[test]
    fn chrome_sends_a_grease_ech_placeholder() {
        let hello = capture(Some(ClientFingerprint::Chrome));

        let body = hello.body(0xfe0d).expect("no encrypted_client_hello");
        assert_eq!(body[0], 0x00, "not an outer ECH");

        // 0x00 outer, kdf u16, aead u16, config_id u8, then the encapsulated
        // key as a length-prefixed payload. Thirty-two bytes means X25519,
        // which is the KEM browsers GREASE with; P-256 would be sixty-five and
        // would stand out for it.
        assert_eq!(u16::from_be_bytes([body[6], body[7]]), 32);
    }

    #[test]
    fn grease_ech_does_not_cost_us_tls12() {
        // rustls pins TLS 1.3 for real ECH. GREASE negotiates nothing, so it
        // must not - Chrome offers both versions and a placeholder extension.
        let hello = capture(Some(ClientFingerprint::Chrome));
        let versions = hello.u16_list(0x002b, 1);

        assert_eq!(&versions[1..], &[0x0304, 0x0303], "{versions:04x?}");
    }

    #[test]
    fn chrome_does_not_send_the_scsv() {
        let hello = capture(Some(ClientFingerprint::Chrome));

        // rustls says "I will not renegotiate" with this pseudo-suite; the
        // browser says it with an extension. Sending both, or the wrong one,
        // is as visible as any real difference.
        assert!(!hello.cipher_suites.contains(&0x00ff));
        assert_eq!(hello.body(EXT_RENEGOTIATION_INFO), Some(&[0x00][..]));
    }

    #[test]
    fn chrome_offers_chromes_alpn() {
        let hello = capture(Some(ClientFingerprint::Chrome));

        // ALPN(16): u16 list length, then length-prefixed protocols.
        assert_eq!(
            hello.body(0x0010),
            Some(
                &[
                    0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p',
                    b'/', b'1', b'.', b'1'
                ][..]
            )
        );
    }

    #[test]
    fn no_fingerprint_leaves_the_hello_exactly_as_it_was() {
        let hello = capture(None);

        assert!(!hello.cipher_suites.iter().copied().any(is_grease));
        assert!(!hello.types().into_iter().any(is_grease));
        assert!(hello.body(EXT_SIGNED_CERTIFICATE_TIMESTAMP).is_none());
        assert!(hello.body(EXT_APPLICATION_SETTINGS).is_none());
        assert!(hello.body(0xfe0d).is_none(), "unasked-for GREASE ECH");
        // The SCSV is still how rustls signals no renegotiation.
        assert!(hello.cipher_suites.contains(&0x00ff));
    }

    #[test]
    fn randomized_greases_and_nothing_more() {
        let hello = capture(Some(ClientFingerprint::Randomized));

        assert!(is_grease(hello.cipher_suites[0]));
        // Not a browser and not claiming to be: no browser-specific extension
        // and no invented cipher list.
        assert!(hello.body(EXT_APPLICATION_SETTINGS).is_none());
        assert!(hello.body(0xfe0d).is_none());
        assert!(hello.cipher_suites.contains(&0x00ff));
    }
}
