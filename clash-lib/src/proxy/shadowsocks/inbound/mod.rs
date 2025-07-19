mod datagram;

use crate::{
    Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::new_io_error},
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
use shadowsocks::{ProxySocket, context::Context, net::AcceptOpts, relay::Address};
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
            udp_closer: Default::default(),
        }
    }

    fn get_server_config(
        &self,
    ) -> std::io::Result<shadowsocks::config::ServerConfig> {
        shadowsocks::config::ServerConfig::new(
            self.addr,
            &self.password,
            map_cipher(&self.cipher)?,
        )
        .map_err(|e| {
            new_io_error(format!("Failed to create Shadowsocks config: {e}"))
        })
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
        let context = Context::new_shared(shadowsocks::config::ServerType::Server);
        let config = self.get_server_config()?;

        // TODO: support multiple users
        // let user_manager = shadowsocks::config::ServerUserManager::new();
        //
        // config.set_user_manager(user_manager);

        let listener = try_create_dualstack_tcplistener(self.addr)?;

        let ss_listener = shadowsocks::relay::tcprelay::ProxyListener::from_listener(
            context,
            shadowsocks::net::TcpListener::from_listener(
                listener,
                AcceptOpts::default(),
            )?,
            &config,
        );

        loop {
            let (mut socket, _) = match ss_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to accept Shadowsocks TCP connection: {}", e);
                    continue;
                }
            };

            debug!(
                "Accepted Shadowsocks TCP connection from {}",
                socket.get_ref().peer_addr()?
            );

            let Ok(src_addr) = socket.get_ref().peer_addr() else {
                warn!("Failed to get peer address for Shadowsocks TCP connection");
                continue;
            };

            if !self.allow_lan
                && src_addr.ip() != socket.get_ref().local_addr()?.ip()
            {
                warn!("Connection from {} is not allowed", src_addr.to_canonical());
                continue;
            }

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
                dispatcher.dispatch_stream(sess, Box::new(socket)).await;
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        let context = Context::new_shared(shadowsocks::config::ServerType::Server);
        let config = self.get_server_config()?;

        // TODO: support multiple users
        // let user_manager = shadowsocks::config::ServerUserManager::new();
        //
        // config.set_user_manager(user_manager);

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
            iface: None, // No interface for Shadowsocks UDP
            ..Default::default()
        };

        let closer = dispatcher.dispatch_datagram(sess, wrapped_socket).await;
        let mut g = self.udp_closer.lock().await;
        *g = Some(closer);
        Ok(())
    }
}
