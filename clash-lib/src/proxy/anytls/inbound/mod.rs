mod datagram;

use crate::{
    Dispatcher,
    config::internal::listener::InboundUser,
    proxy::{
        AnyStream,
        inbound::InboundHandlerTrait,
        utils::{ToCanonical, try_create_dualstack_tcplistener},
    },
    session::{Network, Session, SocksAddr, Type},
};
use async_trait::async_trait;
use bytes::BufMut;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use self::datagram::InboundDatagramAnytls;

// AnyTLS frame command bytes — same as outbound.
const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;

/// The magic hostname used by the client for UDP-over-TCP v2 sessions.
const UDP_OVER_TCP_V2_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";

/// Duplex and relay buffer sizes (mirrors the outbound).
const DUPLEX_BUFFER_SIZE: usize = 64 * 1024;
const RELAY_BUFFER_SIZE: usize = 16 * 1024;

pub struct InboundOptions {
    pub addr: SocketAddr,
    /// Single-user fallback password (plaintext). Used when `users_rx` yields
    /// an empty list.
    pub password: String,
    /// File path or inline PEM certificate chain (detected by `-----BEGIN`).
    pub certificate: String,
    /// File path or inline PEM private key (detected by `-----BEGIN`).
    pub private_key: String,
    pub allow_lan: bool,
    pub dispatcher: Arc<Dispatcher>,
    pub fw_mark: Option<u32>,
    /// Watch receiver for the live user list.
    pub users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
}

pub struct AnytlsInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    tls_acceptor: TlsAcceptor,
    password: String,
    users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
}

impl Drop for AnytlsInbound {
    fn drop(&mut self) {
        warn!("AnyTLS inbound listener on {} stopped", self.addr);
    }
}

impl AnytlsInbound {
    pub fn new(opts: InboundOptions) -> std::io::Result<Self> {
        let tls_acceptor = build_tls_acceptor(&opts.certificate, &opts.private_key)?;
        Ok(Self {
            addr: opts.addr,
            allow_lan: opts.allow_lan,
            dispatcher: opts.dispatcher,
            fw_mark: opts.fw_mark,
            tls_acceptor,
            password: opts.password,
            users_rx: opts.users_rx,
        })
    }
}

/// Build a TLS acceptor from PEM certificate and private key.
/// Strings containing `-----BEGIN` are treated as inline PEM; otherwise
/// they are interpreted as file paths.
fn build_tls_acceptor(
    certificate: &str,
    private_key: &str,
) -> std::io::Result<TlsAcceptor> {
    let cert_pem = if certificate.contains("-----BEGIN") {
        certificate.to_owned()
    } else {
        std::fs::read_to_string(certificate).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("failed to read anytls certificate '{certificate}': {e}"),
            )
        })?
    };

    let key_pem = if private_key.contains("-----BEGIN") {
        private_key.to_owned()
    } else {
        std::fs::read_to_string(private_key).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("failed to read anytls private key '{private_key}': {e}"),
            )
        })?
    };

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .filter_map(|r| {
                r.map_err(|e| warn!("failed to parse anytls certificate: {e}"))
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

/// Build an O(1) password lookup map from the user list.
///
/// Maps SHA256(password) → user name (`""` for single-user mode).
/// If `users` is empty, falls back to `fallback_password`.
pub fn build_user_map(
    users: &[InboundUser],
    fallback_password: &str,
) -> Arc<HashMap<[u8; 32], String>> {
    let mut map = HashMap::new();
    if users.is_empty() {
        let hash: [u8; 32] = Sha256::digest(fallback_password.as_bytes()).into();
        map.insert(hash, String::new());
    } else {
        for u in users {
            let hash: [u8; 32] = Sha256::digest(u.password.as_bytes()).into();
            map.insert(hash, u.name.clone());
        }
    }
    Arc::new(map)
}

/// Read one AnyTLS frame: `CMD(1) | StreamID(u32-BE) | DataLen(u16-BE) | Data`.
async fn read_frame(
    reader: &mut (impl AsyncRead + Unpin),
) -> std::io::Result<(u8, u32, Vec<u8>)> {
    let command = reader.read_u8().await?;
    let stream_id = reader.read_u32().await?;
    let data_len = reader.read_u16().await? as usize;
    let mut data = vec![0u8; data_len];
    if data_len > 0 {
        reader.read_exact(&mut data).await?;
    }
    Ok((command, stream_id, data))
}

/// Write one AnyTLS frame to `writer`.
async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    command: u8,
    stream_id: u32,
    data: &[u8],
) -> std::io::Result<()> {
    if data.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "anytls frame payload exceeds 65535 bytes",
        ));
    }
    writer.write_u8(command).await?;
    writer.write_u32(stream_id).await?;
    writer.write_u16(data.len() as u16).await?;
    if !data.is_empty() {
        writer.write_all(data).await?;
    }
    Ok(())
}

/// Handle one accepted TCP connection (runs in a spawned task).
async fn handle_connection(
    raw_stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    acceptor: TlsAcceptor,
    dispatcher: Arc<Dispatcher>,
    user_map: Arc<HashMap<[u8; 32], String>>,
    fw_mark: Option<u32>,
) {
    // ── TLS handshake ────────────────────────────────────────────────────────
    let mut tls_stream = match acceptor.accept(raw_stream).await {
        Ok(s) => s,
        Err(e) => {
            debug!("anytls inbound TLS handshake failed from {src_addr}: {e}");
            return;
        }
    };

    // ── Read 32-byte password hash ───────────────────────────────────────────
    let mut hash_buf = [0u8; 32];
    if let Err(e) = tls_stream.read_exact(&mut hash_buf).await {
        debug!("anytls inbound failed to read password hash from {src_addr}: {e}");
        return;
    }

    let inbound_user = match user_map.get(&hash_buf) {
        Some(name) => {
            if name.is_empty() {
                None
            } else {
                Some(name.clone())
            }
        }
        None => {
            warn!(
                "anytls inbound rejected connection from {src_addr}: wrong password"
            );
            return;
        }
    };

    // ── Skip padding ─────────────────────────────────────────────────────────
    let padding_len = match tls_stream.read_u16().await {
        Ok(n) => n as usize,
        Err(e) => {
            debug!(
                "anytls inbound failed to read padding length from {src_addr}: {e}"
            );
            return;
        }
    };
    if padding_len > 0 {
        let mut skip = vec![0u8; padding_len];
        if let Err(e) = tls_stream.read_exact(&mut skip).await {
            debug!("anytls inbound failed to skip padding from {src_addr}: {e}");
            return;
        }
    }

    // ── Read frames until we have SYN + PSH with destination ─────────────────
    let mut stream_id: Option<u32> = None;
    let destination: SocksAddr;

    'handshake: loop {
        let (cmd, sid, data) = match read_frame(&mut tls_stream).await {
            Ok(f) => f,
            Err(e) => {
                debug!(
                    "anytls inbound failed to read handshake frame from \
                     {src_addr}: {e}"
                );
                return;
            }
        };

        match cmd {
            CMD_SETTINGS | CMD_WASTE => {
                // SETTINGS carries client metadata; we skip it.
            }
            CMD_SYN => {
                stream_id = Some(sid);
            }
            CMD_PSH => {
                if stream_id.is_none() {
                    stream_id = Some(sid);
                }
                // Parse SocksAddr from the PSH frame data.
                let mut cursor = std::io::Cursor::new(data);
                match SocksAddr::read_from(&mut cursor).await {
                    Ok(addr) => {
                        destination = addr;
                        break 'handshake;
                    }
                    Err(e) => {
                        debug!(
                            "anytls inbound failed to parse destination from \
                             {src_addr}: {e}"
                        );
                        return;
                    }
                }
            }
            CMD_FIN | CMD_ALERT => {
                debug!("anytls inbound received early {cmd} from {src_addr}");
                return;
            }
            _ => {}
        }
    }

    let sid = match stream_id {
        Some(s) => s,
        None => {
            warn!("anytls inbound: no SYN received from {src_addr}");
            return;
        }
    };
    let dest = destination;

    debug!(
        "anytls inbound accepted stream_id={sid} dest={dest} from {src_addr} \
         user={:?}",
        inbound_user
    );

    // ── Branch: UDP-over-TCP v2 or plain TCP relay ───────────────────────────
    if dest.host() == UDP_OVER_TCP_V2_MAGIC_HOST {
        handle_udp_session(tls_stream, src_addr, dispatcher, inbound_user, fw_mark)
            .await;
    } else {
        handle_tcp_relay(
            tls_stream,
            src_addr,
            dest,
            sid,
            dispatcher,
            inbound_user,
            fw_mark,
        )
        .await;
    }
}

/// Handle a UDP-over-TCP v2 session.
///
/// After the AnyTLS handshake the client sends:
///   `u8(isConnect=1) | SocksAddr(real_udp_destination)`
/// then exchanges length-prefixed UDP payloads.
async fn handle_udp_session(
    mut tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    src_addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    inbound_user: Option<String>,
    fw_mark: Option<u32>,
) {
    // Read UoT v2 connect header.
    let is_connect = match tls_stream.read_u8().await {
        Ok(b) => b,
        Err(e) => {
            debug!(
                "anytls inbound UoT: failed to read isConnect from {src_addr}: {e}"
            );
            return;
        }
    };
    if is_connect != 1 {
        warn!(
            "anytls inbound UoT: unexpected isConnect={is_connect} from {src_addr}"
        );
        return;
    }

    let real_dest = match SocksAddr::read_from(&mut tls_stream).await {
        Ok(a) => a,
        Err(e) => {
            debug!(
                "anytls inbound UoT: failed to read real destination from \
                 {src_addr}: {e}"
            );
            return;
        }
    };

    debug!(
        "anytls inbound UoT session: src={src_addr} dest={real_dest} user={:?}",
        inbound_user
    );

    let inner: AnyStream = Box::new(tls_stream);
    let datagram = InboundDatagramAnytls::new(inner, real_dest.clone());

    let sess = Session {
        network: Network::Udp,
        typ: Type::Anytls,
        source: src_addr,
        so_mark: fw_mark,
        destination: real_dest,
        inbound_user,
        ..Default::default()
    };

    let _ = dispatcher.dispatch_datagram(sess, Box::new(datagram)).await;
}

/// Handle a plain TCP relay session (the common case).
///
/// After the handshake we set up a duplex and relay frames bidirectionally.
async fn handle_tcp_relay(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    src_addr: SocketAddr,
    dest: SocksAddr,
    stream_id: u32,
    dispatcher: Arc<Dispatcher>,
    inbound_user: Option<String>,
    fw_mark: Option<u32>,
) {
    let (mut remote_read, mut remote_write) = tokio::io::split(tls_stream);
    let (app_stream, relay_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut relay_read, mut relay_write) = tokio::io::split(relay_stream);

    let cancel = CancellationToken::new();
    let cancel_a = cancel.clone();
    let cancel_b = cancel;

    // Task A: relay_read (from dispatcher) → CMD_PSH frames → remote_write
    tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
        loop {
            tokio::select! {
                biased;
                _ = cancel_a.cancelled() => break,
                result = relay_read.read(&mut buf) => {
                    let n = match result {
                        Ok(n) => n,
                        Err(err) => {
                            debug!("anytls inbound relay read error (src={src_addr}): {err}");
                            cancel_a.cancel();
                            break;
                        }
                    };
                    if n == 0 {
                        // Dispatcher closed its end — send FIN to client.
                        if let Err(err) = write_frame(&mut remote_write, CMD_FIN, stream_id, &[]).await {
                            debug!("anytls inbound send FIN failed (src={src_addr}): {err}");
                        }
                        let _ = remote_write.flush().await;
                        cancel_a.cancel();
                        break;
                    }
                    let mut psh_header = bytes::BytesMut::with_capacity(7);
                    psh_header.put_u8(CMD_PSH);
                    psh_header.put_u32(stream_id);
                    psh_header.put_u16(n as u16);
                    // Write header + data together to reduce syscalls.
                    if let Err(err) = remote_write.write_all(&psh_header).await {
                        debug!("anytls inbound PSH header write failed (src={src_addr}): {err}");
                        cancel_a.cancel();
                        break;
                    }
                    if let Err(err) = remote_write.write_all(&buf[..n]).await {
                        debug!("anytls inbound PSH data write failed (src={src_addr}): {err}");
                        cancel_a.cancel();
                        break;
                    }
                    if let Err(err) = remote_write.flush().await {
                        debug!("anytls inbound flush failed (src={src_addr}): {err}");
                        cancel_a.cancel();
                        break;
                    }
                }
            }
        }
    });

    // Task B: remote_read → CMD_PSH frames → relay_write (to dispatcher)
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel_b.cancelled() => break,
                result = read_frame(&mut remote_read) => {
                    let (cmd, _sid, data) = match result {
                        Ok(f) => f,
                        Err(err) => {
                            debug!("anytls inbound read frame error (src={src_addr}): {err}");
                            cancel_b.cancel();
                            break;
                        }
                    };
                    match cmd {
                        CMD_PSH => {
                            if let Err(err) = relay_write.write_all(&data).await {
                                debug!("anytls inbound relay write failed (src={src_addr}): {err}");
                                cancel_b.cancel();
                                break;
                            }
                        }
                        CMD_FIN => {
                            // Client finished sending — shutdown the write side.
                            let _ = relay_write.shutdown().await;
                            cancel_b.cancel();
                            break;
                        }
                        CMD_ALERT => {
                            let msg = String::from_utf8_lossy(&data);
                            warn!("anytls inbound alert from {src_addr}: {msg}");
                            let _ = relay_write.shutdown().await;
                            cancel_b.cancel();
                            break;
                        }
                        // Control frames we don't need to act on server-side.
                        CMD_WASTE | CMD_SYN | CMD_SETTINGS => {}
                        _ => {}
                    }
                }
            }
        }
    });

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Anytls,
        source: src_addr,
        so_mark: fw_mark,
        destination: dest,
        inbound_user,
        ..Default::default()
    };

    dispatcher.dispatch_stream(sess, Box::new(app_stream)).await;
}

#[async_trait]
impl InboundHandlerTrait for AnytlsInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false // UDP is tunnelled over TCP; no separate UDP listener needed.
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let listener = try_create_dualstack_tcplistener(self.addr)?;
        let local_addr = listener.local_addr()?;
        let local_ip = local_addr.ip();

        let mut users_rx = self.users_rx.clone();
        let mut user_map =
            build_user_map(&users_rx.borrow_and_update(), &self.password);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, src_addr) = match result {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("anytls inbound {}: accept error: {e}", self.addr);
                            continue;
                        }
                    };

                    let src_addr = src_addr.to_canonical();

                    if !self.allow_lan
                        && !local_ip.is_unspecified()
                        && src_addr.ip() != local_ip
                    {
                        warn!(
                            "anytls inbound {}: connection from {} rejected (not allowed)",
                            self.addr, src_addr
                        );
                        continue;
                    }

                    let acceptor = self.tls_acceptor.clone();
                    let dispatcher = self.dispatcher.clone();
                    let map = Arc::clone(&user_map);
                    let fw_mark = self.fw_mark;

                    tokio::spawn(async move {
                        handle_connection(
                            stream, src_addr, acceptor, dispatcher, map, fw_mark,
                        )
                        .await;
                    });
                }

                Ok(()) = users_rx.changed() => {
                    let users = users_rx.borrow_and_update().clone();
                    info!(
                        "anytls inbound {}: user list updated ({} users)",
                        self.addr,
                        users.len()
                    );
                    user_map = build_user_map(&users, &self.password);
                }
            }
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        // UDP is handled inside TCP connections via UoT v2; no UDP socket.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Install the rustls crypto provider once per test binary.
    /// Tests that use rustls directly must call this.
    fn install_crypto_provider() {
        #[cfg(feature = "aws-lc-rs")]
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn make_users(pairs: &[(&str, &str)]) -> Vec<InboundUser> {
        pairs
            .iter()
            .map(|(name, pw)| InboundUser {
                name: name.to_string(),
                password: pw.to_string(),
            })
            .collect()
    }

    #[test]
    fn test_build_user_map_empty_uses_fallback() {
        let map = build_user_map(&[], "secret");
        let hash: [u8; 32] = Sha256::digest("secret".as_bytes()).into();
        assert!(map.contains_key(&hash), "fallback hash must be in the map");
        assert_eq!(
            map.get(&hash).unwrap(),
            "",
            "fallback user name must be empty"
        );
    }

    #[test]
    fn test_build_user_map_correct_password_found() {
        let users = make_users(&[("alice", "pass123")]);
        let map = build_user_map(&users, "ignored");
        let hash: [u8; 32] = Sha256::digest("pass123".as_bytes()).into();
        assert_eq!(map.get(&hash).map(String::as_str), Some("alice"));
    }

    #[test]
    fn test_build_user_map_wrong_password_not_found() {
        let users = make_users(&[("alice", "correct")]);
        let map = build_user_map(&users, "ignored");
        let bad_hash: [u8; 32] = Sha256::digest("wrong".as_bytes()).into();
        assert!(
            !map.contains_key(&bad_hash),
            "wrong password must not be in map"
        );
    }

    #[test]
    fn test_build_user_map_multi_user() {
        let users = make_users(&[("alice", "pw_a"), ("bob", "pw_b")]);
        let map = build_user_map(&users, "ignored");
        assert_eq!(map.len(), 2);

        let hash_a: [u8; 32] = Sha256::digest("pw_a".as_bytes()).into();
        let hash_b: [u8; 32] = Sha256::digest("pw_b".as_bytes()).into();
        assert_eq!(map.get(&hash_a).map(String::as_str), Some("alice"));
        assert_eq!(map.get(&hash_b).map(String::as_str), Some("bob"));
    }

    // ── TLS cert loading ───────────────────────────────────────────────────────

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

        let result = build_tls_acceptor(&cert_pem, &key_pem);
        assert!(
            result.is_ok(),
            "build_tls_acceptor must succeed with valid inline PEM: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_tls_acceptor_invalid_cert_fails() {
        install_crypto_provider();
        let result = build_tls_acceptor(
            "-----BEGIN CERTIFICATE-----\nbaddata\n-----END CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----\nbaddata\n-----END PRIVATE KEY-----",
        );
        assert!(
            result.is_err(),
            "build_tls_acceptor must fail with invalid PEM"
        );
    }

    // ── Protocol-level TLS + handshake integration test ───────────────────────

    /// Tests the complete AnyTLS server-side handshake parsing over a real TLS
    /// connection (no Dispatcher needed — we test only the protocol framing).
    #[tokio::test]
    async fn test_anytls_handshake_parsing_over_tls() {
        install_crypto_provider();
        use bytes::BufMut;
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::TlsConnector;

        let rcgen::CertifiedKey {
            cert,
            signing_key: key_pair,
        } = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen cert generation failed");
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        // Keep the DER bytes around so we can trust it on the client side.
        let cert_der = cert.der().clone();

        let acceptor = build_tls_acceptor(&cert_pem, &key_pem).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let password = "integration_test_pw";
        let hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
        let expected_host = "example.com";
        let expected_port: u16 = 8080;

        // Server task: accept, do TLS, parse AnyTLS handshake, verify fields.
        let server_task = tokio::spawn(async move {
            let (raw, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(raw).await.unwrap();

            // 32-byte SHA256 password hash
            let mut hash_buf = [0u8; 32];
            tls.read_exact(&mut hash_buf).await.unwrap();
            assert_eq!(hash_buf, hash, "password hash mismatch");

            // u16 padding length (must be 0 in test)
            let pad = tls.read_u16().await.unwrap();
            assert_eq!(pad, 0, "padding length must be 0");

            // SETTINGS frame
            let (cmd, sid, _) = read_frame(&mut tls).await.unwrap();
            assert_eq!(cmd, CMD_SETTINGS, "expected SETTINGS frame");
            assert_eq!(sid, 0, "SETTINGS stream_id must be 0");

            // SYN frame
            let (cmd, sid, data) = read_frame(&mut tls).await.unwrap();
            assert_eq!(cmd, CMD_SYN, "expected SYN frame");
            assert_eq!(sid, 1, "SYN stream_id must be 1");
            assert!(data.is_empty(), "SYN data must be empty");

            // PSH frame with destination
            let (cmd, sid, payload) = read_frame(&mut tls).await.unwrap();
            assert_eq!(cmd, CMD_PSH, "expected PSH frame");
            assert_eq!(sid, 1, "PSH stream_id must be 1");

            let mut cursor = std::io::Cursor::new(payload);
            let dest = SocksAddr::read_from(&mut cursor).await.unwrap();
            assert_eq!(dest.host(), expected_host);
            assert_eq!(dest.port(), expected_port);
        });

        // Client task: connect via TLS, send AnyTLS handshake.
        let client_task = tokio::spawn(async move {
            // Build a rustls client config that trusts our self-signed cert.
            let mut root_store = rustls::RootCertStore::empty();
            root_store
                .add(rustls::pki_types::CertificateDer::from(cert_der))
                .unwrap();
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(tls_config));
            let raw = TcpStream::connect(server_addr).await.unwrap();
            let mut stream = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    raw,
                )
                .await
                .unwrap();

            let settings = format!(
                "v=2\nclient=clash-rs-test\\
                 npadding-md5=47edb1f4ed8a99480bf416d178311f10"
            );
            let dest =
                SocksAddr::try_from((expected_host.to_owned(), expected_port))
                    .unwrap();
            let mut addr_buf = bytes::BytesMut::new();
            dest.write_buf(&mut addr_buf);

            let mut handshake = bytes::BytesMut::new();
            handshake.put_slice(&hash);
            handshake.put_u16(0); // no padding
            // SETTINGS frame (stream_id=0)
            handshake.put_u8(CMD_SETTINGS);
            handshake.put_u32(0);
            handshake.put_u16(settings.len() as u16);
            handshake.put_slice(settings.as_bytes());
            // SYN frame (stream_id=1)
            handshake.put_u8(CMD_SYN);
            handshake.put_u32(1);
            handshake.put_u16(0);
            // PSH frame (stream_id=1, destination)
            handshake.put_u8(CMD_PSH);
            handshake.put_u32(1);
            handshake.put_u16(addr_buf.len() as u16);
            handshake.put_slice(&addr_buf);

            stream.write_all(&handshake).await.unwrap();
            stream.flush().await.unwrap();
        });

        tokio::try_join!(server_task, client_task).unwrap();
    }
}
