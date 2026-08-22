use async_trait::async_trait;
use rustls::{
    ClientConfig, RootCertStore, client::RealityConfig, pki_types::ServerName,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use std::{
    io,
    ops::Deref,
    sync::{Arc, OnceLock, atomic::AtomicBool},
};

use crate::{
    common::{
        tls::{GLOBAL_ROOT_STORE, apply_client_fingerprint},
        tls_fingerprint::{ClientFingerprint, PinnedSchemeVerifier},
    },
    proxy::{
        AnyStream,
        transport::{Transport, VisionOptions, splice_tls::SplicableTlsStream},
    },
};

fn init_roots() -> Arc<RootCertStore> {
    Arc::new(webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect())
}

#[derive(Clone)]
pub struct Client(Arc<ClientInner>);

impl Client {
    /// `fingerprint` shapes the ClientHello, and this is the case the whole
    /// feature exists for: Reality hides inside a TLS handshake to a real
    /// site, and that only works while the handshake is indistinguishable
    /// from the client it claims to come from.
    pub fn new(
        sni: String,
        public_key: [u8; 32],
        short_id: Vec<u8>,
        fingerprint: Option<ClientFingerprint>,
    ) -> Self {
        Self(Arc::new(ClientInner {
            sni,
            public_key,
            short_id,
            roots: OnceLock::new(),
            fingerprint,
        }))
    }
}

impl Deref for Client {
    type Target = ClientInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Client {
    /// Connect with Reality TLS and return the concrete `TlsStream` (not
    /// boxed).  Used by XTLS-Vision splice mode so VisionStream can later
    /// bypass the TLS layer for raw-copy.
    pub async fn connect_tls(
        &self,
        stream: AnyStream,
    ) -> io::Result<TlsStream<AnyStream>> {
        let reality = RealityConfig::new(self.public_key, self.short_id.clone())
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?;

        let mut tls_config = self
            .client_config_builder()?
            .with_reality(reality)
            .with_no_client_auth();
        apply_client_fingerprint(&mut tls_config, self.fingerprint);

        let sni: ServerName<'_> =
            ServerName::try_from(self.sni.clone()).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?;

        TlsConnector::from(std::sync::Arc::new(tls_config))
            .connect(sni, stream)
            .await
            .map_err(io::Error::other)
    }
}

impl ClientInner {
    /// A config builder carrying the fingerprint's provider and verifier.
    ///
    /// Reality cannot use the shared helper: `with_reality` wraps whatever
    /// verifier is in place at that moment, so ours has to be installed first
    /// and the Reality one layered on top of it.
    fn client_config_builder(
        &self,
    ) -> io::Result<
        rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>,
    > {
        let Some(fingerprint) = self.fingerprint else {
            return Ok(ClientConfig::builder().with_root_certificates(
                self.roots.get_or_init(init_roots).clone(),
            ));
        };

        let base = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .ok_or_else(|| {
                io::Error::other("no default crypto provider installed")
            })?;

        let verifier =
            rustls::client::WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
                .build()
                .map_err(io::Error::other)?;

        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            match fingerprint.signature_schemes() {
                Some(schemes) => {
                    Arc::new(PinnedSchemeVerifier::new(verifier, schemes))
                }
                None => verifier,
            };

        let builder =
            ClientConfig::builder_with_provider(fingerprint.crypto_provider(base));

        // GREASE ECH is stored on the builder, not on the finished config, so
        // it has to be decided here.
        let builder = match fingerprint.ech_mode() {
            Some(mode) => builder.with_ech(mode),
            None => builder.with_safe_default_protocol_versions(),
        }
        .map_err(io::Error::other)?;

        Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(verifier))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        self.connect_tls(stream)
            .await
            .map(|x| Box::new(x) as AnyStream)
    }

    /// Establish a Reality TLS connection and return the stream together with
    /// `VisionOptions` (a pair of `Arc<AtomicBool>` splice flags) that allow
    /// the upper `VisionStream` to signal this layer when XTLS-splice mode is
    /// triggered.
    ///
    /// ## Layer stack
    ///
    /// ```text
    ///  VisionStream          (owns VisionOptions – writes the flags)
    ///    └─ VlessStream      (VLESS framing)
    ///        └─ SplicableTlsStream  (reads the flags; bypasses TLS when set)
    ///            └─ Reality TLS
    ///                └─ TCP
    /// ```
    ///
    /// ## Handshake / splice sequence
    ///
    /// ```text
    ///  Client                                  Xray server
    ///    |                                          |
    ///    |---------- Reality TLS handshake -------->|
    ///    |<--------- Reality TLS handshake ---------|
    ///    |   (all traffic above is Reality-TLS encrypted)
    ///    |                                          |
    ///    |========== Vision framing mode ===========|
    ///    |--[UUID][CMD=0x00][inner TLS ClientHello]->|  Vision-framed inner TLS
    ///    |<-[UUID][CMD=0x00][inner TLS ServerHello]--|
    ///    |<-[CMD=0x02][inner TLS AppData]------------|  server triggers splice
    ///    |--[CMD=0x02][inner TLS AppData]----------->|  client triggers splice
    ///    |                                          |
    ///    |  (both sides received CMD_DIRECT)        |
    ///    |                                          |
    ///    |========== Splice mode (raw TCP) ==========|
    ///    |--[raw inner-TLS AppData]----------------->|  no outer TLS encryption
    ///    |<-[raw inner-TLS AppData]------------------|
    /// ```
    ///
    /// On `CMD_PADDING_DIRECT` (0x02):
    /// - `VisionStream` sets `read_flag` / `write_flag` to `true`.
    /// - `SplicableTlsStream` detects the flags and bypasses Reality TLS,
    ///   reading/writing raw bytes directly on the TCP socket.
    async fn proxy_stream_spliced(
        &self,
        stream: AnyStream,
    ) -> io::Result<(AnyStream, Option<VisionOptions>)> {
        let read_flag = Arc::new(AtomicBool::new(false));
        let write_flag = Arc::new(AtomicBool::new(false));
        let tls_stream = self.connect_tls(stream).await?;
        let splittable = SplicableTlsStream::new(
            tls_stream,
            Arc::clone(&read_flag),
            Arc::clone(&write_flag),
        );
        let opts = VisionOptions {
            read_flag,
            write_flag,
        };
        Ok((Box::new(splittable), Some(opts)))
    }
}

pub struct ClientInner {
    sni: String,
    public_key: [u8; 32],
    short_id: Vec<u8>,
    // cached for performance
    roots: OnceLock<Arc<RootCertStore>>,
    fingerprint: Option<ClientFingerprint>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        crate::setup_default_crypto_provider();
    }

    fn make_stream() -> AnyStream {
        let (client, _server) = tokio::io::duplex(1024);
        Box::new(client)
    }

    #[test]
    fn test_new() {
        let c = Client::new(
            "example.com".to_string(),
            [1u8; 32],
            vec![0xab, 0xcd],
            None,
        );
        assert_eq!(c.sni, "example.com");
        assert_eq!(c.public_key, [1u8; 32]);
        assert_eq!(c.short_id, vec![0xab, 0xcd]);
    }

    // short_id > 8 bytes → RealityConfig::new() fails → InvalidInput
    #[tokio::test]
    async fn test_short_id_too_long() {
        setup();
        let c =
            Client::new("example.com".to_string(), [0u8; 32], vec![0u8; 9], None);
        let err = c.proxy_stream(make_stream()).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    // Invalid SNI → ServerName::try_from fails → InvalidInput
    #[tokio::test]
    async fn test_invalid_sni() {
        setup();
        let c = Client::new("".to_string(), [0u8; 32], vec![0u8; 4], None);
        let err = c.proxy_stream(make_stream()).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    // Valid params, server side dropped → TLS handshake error (not InvalidInput)
    #[tokio::test]
    async fn test_handshake_error_on_closed_peer() {
        setup();
        let c =
            Client::new("example.com".to_string(), [0u8; 32], vec![0u8; 4], None);
        let err = c.proxy_stream(make_stream()).await.err().unwrap();
        assert_ne!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
