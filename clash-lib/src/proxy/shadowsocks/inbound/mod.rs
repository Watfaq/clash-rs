mod datagram;

use crate::{
    Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::new_io_error},
    config::internal::listener::ShadowsocksUser,
    proxy::{
        inbound::InboundHandlerTrait,
        shadowsocks::{inbound::datagram::InboundShadowsocksDatagram, map_cipher},
        utils::{
            ToCanonical, apply_tcp_options, new_udp_socket,
            try_create_dualstack_tcplistener,
        },
    },
    session::{Network, Session, SocksAddr, Type},
};

use async_trait::async_trait;
use base64::Engine as _;
use shadowsocks::{
    ProxySocket,
    context::Context as SsContext,
    relay::{
        Address,
        tcprelay::{
            crypto_io::{CryptoRead, CryptoStream, CryptoWrite, StreamType},
            proxy_stream::protocol::TcpRequestHeader,
        },
    },
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::RwLock,
};
use tracing::{debug, warn};

/// Sentinel key for listener-wide (total) traffic in `user_traffic_stats`.
pub const STAT_KEY_TOTAL: &str = "__total__";

// ---------------------------------------------------------------------------
// Per-user traffic statistics
// ---------------------------------------------------------------------------

/// Per-user traffic statistics counters.
#[derive(Debug, Default)]
pub struct UserTrafficStat {
    /// Bytes sent FROM the client (upload).
    pub upload_bytes: Arc<AtomicU64>,
    /// Bytes sent TO the client (download).
    pub download_bytes: Arc<AtomicU64>,
}

impl UserTrafficStat {
    /// Returns `(upload, download)` as a snapshot.
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.upload_bytes.load(Ordering::Relaxed),
            self.download_bytes.load(Ordering::Relaxed),
        )
    }

    /// Returns `(upload, download)` and atomically resets both to 0.
    pub fn snapshot_and_reset(&self) -> (u64, u64) {
        (
            self.upload_bytes.swap(0, Ordering::Relaxed),
            self.download_bytes.swap(0, Ordering::Relaxed),
        )
    }
}

/// Shared, lock-protected map of user-name → traffic stat counters.
/// The special key [`STAT_KEY_TOTAL`] holds listener-wide totals.
pub type SharedUserStats =
    Arc<RwLock<HashMap<String, Arc<UserTrafficStat>>>>;

// ---------------------------------------------------------------------------
// CountingStream — wraps any AsyncRead+AsyncWrite and tallies bytes.
// ---------------------------------------------------------------------------

/// Wraps an inner stream and increments `Arc<AtomicU64>` counters as bytes
/// flow.
///
/// * `poll_read`  → data arriving FROM the client  → increments **upload**
/// * `poll_write` → data being sent TO the client  → increments **download**
pub struct CountingStream<S> {
    inner: S,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

impl<S: Unpin> Unpin for CountingStream<S> {}

impl<S> CountingStream<S> {
    pub fn new(inner: S, stat: &UserTrafficStat) -> Self {
        Self {
            inner,
            upload: stat.upload_bytes.clone(),
            download: stat.download_bytes.clone(),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let delta = buf.filled().len() - before;
        if delta > 0 {
            self.upload.fetch_add(delta as u64, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.download.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// CryptoServerStream — exposes user_key() after handshake
// ---------------------------------------------------------------------------

/// Wraps [`CryptoStream<S>`] to implement `AsyncRead + AsyncWrite` and expose
/// `user_key()` after handshake.
///
/// This is the key enabler for XrayR-style per-user traffic accounting:
/// [`shadowsocks::relay::tcprelay::proxy_stream::server::ProxyServerStream`]
/// keeps the matched user key in a private field, so we bypass it and use
/// `CryptoStream` directly—which has a public `user_key()` method.
struct CryptoServerStream<S> {
    crypto: CryptoStream<S>,
    context: shadowsocks::context::SharedContext,
}

impl<S: Unpin> Unpin for CryptoServerStream<S> {}

impl<S: AsyncRead + AsyncWrite + Unpin> CryptoServerStream<S> {
    fn new(
        context: shadowsocks::context::SharedContext,
        stream: S,
        method: shadowsocks::crypto::CipherKind,
        key: &[u8],
        user_manager: Option<Arc<shadowsocks::config::ServerUserManager>>,
    ) -> Self {
        const EMPTY_IDENTITY: [bytes::Bytes; 0] = [];
        let crypto = CryptoStream::from_stream_with_identity(
            &context,
            stream,
            StreamType::Server,
            method,
            key,
            &EMPTY_IDENTITY,
            user_manager,
        );
        Self { crypto, context }
    }

    /// Performs the SS handshake and returns the target address.
    ///
    /// After this call, `user_key()` returns the key of the authenticated
    /// user (for AEAD-2022 multi-user mode).
    async fn handshake(&mut self) -> std::io::Result<Address> {
        let method = self.crypto.method();
        let header =
            TcpRequestHeader::read_from(method, self).await?;
        Ok(header.addr())
    }

    /// Returns the raw key of the user authenticated during handshake.
    ///
    /// Returns `None` for non-AEAD-2022 ciphers or single-user mode.
    fn user_key(&self) -> Option<&[u8]> {
        self.crypto.user_key()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for CryptoServerStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.crypto)
            .poll_read_decrypted(cx, &me.context, buf)
            .map_err(std::io::Error::other)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for CryptoServerStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        Pin::new(&mut me.crypto)
            .poll_write_encrypted(cx, buf)
            .map_err(std::io::Error::other)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        me.crypto.poll_flush(cx).map_err(std::io::Error::other)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        me.crypto
            .poll_shutdown(cx)
            .map_err(std::io::Error::other)
    }
}

// ---------------------------------------------------------------------------
// ShadowsocksInbound
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ShadowsocksInbound {
    addr: SocketAddr,
    /// Pre-derived encryption key (ready for `CryptoStream`).
    enc_key: Arc<[u8]>,
    cipher_kind: shadowsocks::crypto::CipherKind,
    udp: bool,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    #[allow(unused)]
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
    users: Vec<ShadowsocksUser>,
    /// Pre-built user manager (for AEAD-2022 multi-user).
    user_manager: Option<Arc<shadowsocks::config::ServerUserManager>>,
    /// Maps raw user key bytes → user name for O(1) post-handshake lookup.
    key_to_user: Arc<HashMap<Vec<u8>, String>>,
    /// Per-user traffic stats plus a [`STAT_KEY_TOTAL`] entry.
    ///
    /// The `__total__` entry is always present and receives bytes from every
    /// connection.  Per-configured-user entries are filled in once the
    /// authenticated `user_key()` is known post-handshake.
    pub user_traffic_stats: SharedUserStats,

    udp_closer: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<u8>>>>,
    /// Original password string (kept for the UDP `ProxySocket` path which
    /// still goes through `ServerConfig`).
    password: String,
}

impl Drop for ShadowsocksInbound {
    fn drop(&mut self) {
        warn!("Shadowsocks inbound listener on {} stopped", self.addr);
    }
}

pub struct InboundOptions {
    pub addr: SocketAddr,
    pub password: String,
    pub udp: bool,
    pub cipher: String,
    pub allow_lan: bool,
    pub dispatcher: Arc<Dispatcher>,
    pub authenticator: ThreadSafeAuthenticator,
    pub fw_mark: Option<u32>,
    pub users: Vec<ShadowsocksUser>,
}

impl ShadowsocksInbound {
    pub fn new(opts: InboundOptions) -> Self {
        // Pre-derive the server key from the password.
        // `ServerConfig::new()` handles both AEAD-2022 base64-PSK and
        // legacy password → HKDF key derivation.
        let cipher_kind = map_cipher(&opts.cipher)
            .expect("cipher validated during config conversion");

        let server_cfg = shadowsocks::config::ServerConfig::new(
            (std::net::Ipv4Addr::UNSPECIFIED, 0),
            &opts.password,
            cipher_kind,
        )
        .expect("password validated during config conversion");

        let enc_key: Arc<[u8]> = server_cfg.key().into();

        // Build per-user manager and reverse lookup map.
        let (user_manager, key_to_user) =
            if !opts.users.is_empty() && cipher_kind.is_aead_2022() {
                let expected_len = cipher_kind.key_len();
                let mut mgr = shadowsocks::config::ServerUserManager::new();
                let mut k2u = HashMap::new();

                for user in &opts.users {
                    if let Ok(raw_key) =
                        base64::engine::general_purpose::STANDARD
                            .decode(&user.password)
                    {
                        if raw_key.len() == expected_len {
                            let ss_user =
                                shadowsocks::config::ServerUser::new(
                                    user.name.clone(),
                                    bytes::Bytes::from(raw_key.clone()),
                                );
                            mgr.add_user(ss_user);
                            k2u.insert(raw_key, user.name.clone());
                        }
                    }
                }

                (Some(Arc::new(mgr)), k2u)
            } else {
                (None, HashMap::new())
            };

        // Pre-populate traffic stats.
        let mut stats: HashMap<String, Arc<UserTrafficStat>> = opts
            .users
            .iter()
            .map(|u| (u.name.clone(), Arc::new(UserTrafficStat::default())))
            .collect();
        stats.insert(
            STAT_KEY_TOTAL.to_string(),
            Arc::new(UserTrafficStat::default()),
        );

        Self {
            addr: opts.addr,
            enc_key,
            cipher_kind,
            udp: opts.udp,
            allow_lan: opts.allow_lan,
            dispatcher: opts.dispatcher,
            authenticator: opts.authenticator,
            fw_mark: opts.fw_mark,
            users: opts.users,
            user_manager,
            key_to_user: Arc::new(key_to_user),
            user_traffic_stats: Arc::new(RwLock::new(stats)),
            udp_closer: Default::default(),
            password: opts.password,
        }
    }

    /// Returns a snapshot of per-user traffic as `(upload_bytes,
    /// download_bytes)`.
    pub async fn get_user_traffic_stats(
        &self,
    ) -> HashMap<String, (u64, u64)> {
        self.user_traffic_stats
            .read()
            .await
            .iter()
            .map(|(name, stat)| (name.clone(), stat.snapshot()))
            .collect()
    }

    /// Returns per-user traffic, resetting all counters to zero after the
    /// read. Equivalent to XrayR's `GetUserTraffic(tag, reset=true)`.
    pub async fn drain_user_traffic_stats(
        &self,
    ) -> HashMap<String, (u64, u64)> {
        self.user_traffic_stats
            .read()
            .await
            .iter()
            .map(|(name, stat)| (name.clone(), stat.snapshot_and_reset()))
            .collect()
    }

    fn get_server_config_for_udp(
        &self,
    ) -> std::io::Result<shadowsocks::config::ServerConfig> {
        let mut config = shadowsocks::config::ServerConfig::new(
            self.addr,
            &self.password,
            self.cipher_kind,
        )
        .map_err(|e| {
            new_io_error(format!("Failed to create Shadowsocks config: {e}"))
        })?;

        if let Some(ref mgr) = self.user_manager {
            config.set_user_manager((**mgr).clone());
        }

        Ok(config)
    }
}

#[async_trait]
impl InboundHandlerTrait for ShadowsocksInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        self.udp
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        use shadowsocks::net::AcceptOpts;

        let context =
            SsContext::new_shared(shadowsocks::config::ServerType::Server);
        let listener = try_create_dualstack_tcplistener(self.addr)?;

        let ss_tcp_listener =
            shadowsocks::net::TcpListener::from_listener(
                listener,
                AcceptOpts::default(),
            )?;

        loop {
            let (raw_stream, peer_addr) = match ss_tcp_listener
                .accept()
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to accept Shadowsocks TCP connection: {}", e);
                    continue;
                }
            };

            debug!(
                "Accepted Shadowsocks TCP connection from {}",
                peer_addr
            );

            let src_addr = peer_addr;

            if !self.allow_lan
                && src_addr.ip()
                    != ss_tcp_listener.local_addr()?.ip()
            {
                warn!("Connection from {} is not allowed", src_addr.to_canonical());
                continue;
            }

            // Build a CryptoServerStream so we can call user_key() after
            // handshake for per-user traffic attribution.
            let mut crypto = CryptoServerStream::new(
                context.clone(),
                raw_stream,
                self.cipher_kind,
                &self.enc_key,
                self.user_manager.clone(),
            );

            let target = match crypto.handshake().await {
                Ok(t) => t,
                Err(e) => {
                    warn!("Failed to perform Shadowsocks handshake: {}", e);
                    continue;
                }
            };

            debug!("Shadowsocks TCP connection target: {:?}", target);

            // ------------------------------------------------------------------
            // XrayR-style per-user traffic attribution.
            //
            // Look up the matched user by their raw key. If found, use their
            // dedicated `UserTrafficStat`; otherwise fall back to `__total__`.
            // ------------------------------------------------------------------
            let stat = {
                let guard = self.user_traffic_stats.read().await;
                let user_stat = crypto.user_key().and_then(|k| {
                    self.key_to_user
                        .get(k)
                        .and_then(|name| guard.get(name).cloned())
                });
                // Also increment __total__ regardless of per-user lookup.
                let total =
                    guard.get(STAT_KEY_TOTAL).cloned().expect("always present");
                (user_stat, total)
            };

            // Wrap the stream: the outer CountingStream targets the per-user
            // stat (if available); the total stat is updated unconditionally
            // by a second inner wrapper.
            let counted = match stat.0 {
                Some(user_stat) => {
                    // Double-wrap: inner counts total, outer counts per-user.
                    let inner = CountingStream::new(crypto, &stat.1);
                    let outer = CountingStream::new(inner, &user_stat);
                    // We need a single Box<dyn ClientStream>. Since the trait
                    // object requires AsyncRead+AsyncWrite+Unpin+Send, use a
                    // helper enum to avoid double-boxing.
                    Either::UserAndTotal(outer)
                }
                None => Either::TotalOnly(CountingStream::new(crypto, &stat.1)),
            };

            // Apply TCP keepalive etc. (need the raw fd; skip for now since
            // CryptoServerStream wraps the raw TcpStream internally and we
            // can't get it back).  The socket was already accepted, so kernel
            // defaults apply.

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Shadowsocks,
                source: src_addr.to_canonical(),
                so_mark: self.fw_mark,
                destination: match target {
                    Address::SocketAddress(addr) => SocksAddr::Ip(addr),
                    Address::DomainNameAddress(domain, port) => {
                        SocksAddr::Domain(domain, port)
                    }
                },
                ..Default::default()
            };

            let dispatcher = self.dispatcher.clone();

            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, Box::new(counted)).await;
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        let context =
            SsContext::new_shared(shadowsocks::config::ServerType::Server);
        let config = self.get_server_config_for_udp()?;

        let socket = new_udp_socket(
            Some(self.addr),
            None,
            #[cfg(target_os = "linux")]
            self.fw_mark,
            None,
        )
        .await?;

        let proxy_socket: ProxySocket<shadowsocks::net::UdpSocket> =
            ProxySocket::from_socket(
                shadowsocks::relay::udprelay::proxy_socket::UdpSocketType::Server,
                context,
                &config,
                socket.into(),
            );

        let dispatcher = self.dispatcher.clone();
        let wrapped_socket =
            Box::new(InboundShadowsocksDatagram::new(proxy_socket));
        let sess = Session {
            network: Network::Udp,
            typ: Type::Shadowsocks,
            source: self.addr,
            so_mark: self.fw_mark,
            iface: None,
            ..Default::default()
        };

        let closer = dispatcher.dispatch_datagram(sess, wrapped_socket).await;
        let mut g = self.udp_closer.lock().await;
        *g = Some(closer);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper: type-erased union of the two stream shapes
// ---------------------------------------------------------------------------

/// Avoids double-boxing by unifying the two counting-stream shapes.
enum Either<A, B> {
    UserAndTotal(A),
    TotalOnly(B),
}

impl<A, B> AsyncRead for Either<A, B>
where
    A: AsyncRead + Unpin,
    B: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::UserAndTotal(s) => Pin::new(s).poll_read(cx, buf),
            Self::TotalOnly(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<A, B> AsyncWrite for Either<A, B>
where
    A: AsyncWrite + Unpin,
    B: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::UserAndTotal(s) => Pin::new(s).poll_write(cx, buf),
            Self::TotalOnly(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::UserAndTotal(s) => Pin::new(s).poll_flush(cx),
            Self::TotalOnly(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::UserAndTotal(s) => Pin::new(s).poll_shutdown(cx),
            Self::TotalOnly(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
