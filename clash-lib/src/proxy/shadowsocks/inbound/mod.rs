mod datagram;

use crate::{
    Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::new_io_error},
    config::internal::listener::InboundUser,
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

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use async_trait::async_trait;
use shadowsocks::{
    ProxySocket,
    config::{ServerConfig, ServerUser, ServerUserManager},
    context::Context,
    relay::{
        Address,
        tcprelay::proxy_stream::server::ProxyServerStream,
    },
};
use std::{net::SocketAddr, sync::Arc};
use tracing::{debug, warn};

#[derive(Clone)]
pub struct ShadowsocksInbound {
    addr: SocketAddr,
    password: String,
    udp: bool,
    cipher: String,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    #[allow(unused)]
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
    users: Vec<InboundUser>,

    udp_closer: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<u8>>>>,
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
    pub users: Vec<InboundUser>,
}

impl ShadowsocksInbound {
    pub fn new(opts: InboundOptions) -> Self {
        Self {
            addr: opts.addr,
            password: opts.password,
            udp: opts.udp,
            cipher: opts.cipher,
            allow_lan: opts.allow_lan,
            dispatcher: opts.dispatcher,
            authenticator: opts.authenticator,
            fw_mark: opts.fw_mark,
            users: opts.users,
            udp_closer: Default::default(),
        }
    }

    fn build_server_config(&self) -> std::io::Result<ServerConfig> {
        ServerConfig::new(self.addr, &self.password, map_cipher(&self.cipher)?).map_err(|e| {
            new_io_error(format!("Failed to create Shadowsocks config: {e}"))
        })
    }

    fn build_user_manager(&self) -> Option<Arc<ServerUserManager>> {
        if self.users.is_empty() {
            return None;
        }
        let mut mgr = ServerUserManager::new();
        for u in &self.users {
            match ServerUser::with_encoded_key(&u.name, &u.password) {
                Ok(user) => mgr.add_user(user),
                Err(e) => warn!("Skipping invalid SS user '{}': {}", u.name, e),
            }
        }
        Some(Arc::new(mgr))
    }
}

/// Peek at the first 48 bytes (salt + EIH) of an SS2022 stream and resolve
/// the authenticated user name without consuming any bytes.
///
/// Returns `None` if the stream has fewer than 48 bytes, the cipher is not
/// AES-256-based (only 2022-blake3-aes-256-gcm is currently supported), or
/// the EIH doesn't match any registered user.
async fn peek_user_identity(
    stream: &tokio::net::TcpStream,
    server_key_bytes: &[u8],
    user_manager: &ServerUserManager,
) -> Option<String> {
    let mut buf = [0u8; 48];
    if stream.peek(&mut buf).await.ok()? < 48 {
        return None;
    }

    let salt = &buf[0..32];
    let eih = &buf[32..48];

    // BLAKE3 KDF — exact context string and key material from shadowsocks crate
    let key_material = [server_key_bytes, salt].concat();
    let subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &key_material);

    // AES-256-ECB single-block decrypt
    let cipher = Aes256::new_from_slice(&subkey[0..32]).ok()?;
    let mut user_hash = aes::Block::default();
    cipher.decrypt_block_b2b(aes::Block::from_slice(eih), &mut user_hash);

    user_manager
        .get_user_by_hash(user_hash.as_slice())
        .map(|u| u.name().to_string())
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
        let context = Context::new_shared(shadowsocks::config::ServerType::Server);
        let config = self.build_server_config()?;
        let user_manager = self.build_user_manager();

        let method = map_cipher(&self.cipher)?;

        // Decode the server password bytes once for EIH subkey derivation.
        let server_key_bytes: Vec<u8> = config.key().to_vec();

        // try_create_dualstack_tcplistener already returns a tokio TcpListener.
        let raw_listener = try_create_dualstack_tcplistener(self.addr)?;

        loop {
            let (stream, src_addr) = match raw_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to accept Shadowsocks TCP connection: {}", e);
                    continue;
                }
            };

            debug!("Accepted Shadowsocks TCP connection from {}", src_addr);

            let src_addr = src_addr.to_canonical();

            if !self.allow_lan && src_addr.ip() != raw_listener.local_addr()?.ip() {
                warn!("Connection from {} is not allowed", src_addr);
                continue;
            }

            // Resolve EIH user identity before handing the stream to shadowsocks.
            // peek() does not consume bytes, so the crate can re-read them normally.
            let inbound_user = if let Some(ref mgr) = user_manager {
                peek_user_identity(&stream, &server_key_bytes, mgr).await
            } else {
                None
            };

            // ProxyServerStream<S> is generic — pass tokio TcpStream directly.
            let mut socket = ProxyServerStream::from_stream_with_user_manager(
                context.clone(),
                stream,
                method,
                config.key(),
                user_manager.clone(),
            );

            let Ok(target) = socket.handshake().await else {
                warn!("Failed to perform Shadowsocks handshake");
                continue;
            };

            debug!("Shadowsocks TCP connection target: {:?}", target);

            if apply_tcp_options(socket.get_ref()).is_err() {
                warn!("Failed to apply TCP options to Shadowsocks socket");
                continue;
            };

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Shadowsocks,
                source: src_addr,
                so_mark: self.fw_mark,
                destination: match target {
                    Address::SocketAddress(addr) => SocksAddr::Ip(addr),
                    Address::DomainNameAddress(domain, port) => {
                        SocksAddr::Domain(domain, port)
                    }
                },
                inbound_user,
                ..Default::default()
            };

            let dispatcher = self.dispatcher.clone();

            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, Box::new(socket)).await;
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        let context = Context::new_shared(shadowsocks::config::ServerType::Server);
        let mut config = self.build_server_config()?;

        if let Some(mgr) = self.build_user_manager() {
            config.set_user_manager(Arc::try_unwrap(mgr).unwrap_or_else(|arc| (*arc).clone()));
        }

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
        let wrapped_socket = Box::new(InboundShadowsocksDatagram::new(proxy_socket));
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
