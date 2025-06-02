mod datagram;

use crate::{
    Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::new_io_error},
    proxy::{
        inbound::InboundHandlerTrait,
        shadowsocks::{inbound::datagram::InboundShadowsocksDatagram, map_cipher},
        utils::{apply_tcp_options, new_udp_socket},
    },
    session::{Network, Session, SocksAddr, Type},
};

use async_trait::async_trait;
use shadowsocks::{ProxySocket, context::Context, net::AcceptOpts, relay::Address};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::warn;

#[derive(Clone)]
pub struct ShadowsocksInbound {
    addr: SocketAddr,
    password: String,
    cipher: String,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
}

impl Drop for ShadowsocksInbound {
    fn drop(&mut self) {
        warn!("Shadowsocks inbound listener on {} stopped", self.addr);
    }
}

impl ShadowsocksInbound {
    pub fn new(
        addr: SocketAddr,
        password: String,
        cipher: String,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            password,
            cipher,
            allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for ShadowsocksInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        true
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let context = Context::new_shared(shadowsocks::config::ServerType::Server);
        let mut config = shadowsocks::config::ServerConfig::new(
            &self.addr.into(),
            &self.password,
            map_cipher(&self.cipher)?,
        )
        .map_err(|e| {
            new_io_error(format!("Failed to create Shadowsocks config: {}", e))
        })?;

        // TODO: support multiple users
        let user_manager = shadowsocks::config::ServerUserManager::new();

        config.set_user_manager(user_manager);

        let listener = TcpListener::bind(self.addr).await?;

        let ss_listener = shadowsocks::relay::tcprelay::ProxyListener::from_listener(
            context,
            shadowsocks::net::TcpListener::from_listener(
                listener,
                AcceptOpts::default(),
            )?,
            &config,
        );

        loop {
            let (mut socket, _) = ss_listener.accept().await?;
            let src_addr = socket.get_ref().peer_addr()?;

            if !self.allow_lan
                && src_addr.ip() != socket.get_ref().local_addr()?.ip()
            {
                warn!("Connection from {} is not allowed", src_addr);
                continue;
            }

            let target = socket.handshake().await?;

            let socket = apply_tcp_options(socket.into_inner())?;

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
        let mut config = shadowsocks::config::ServerConfig::new(
            &self.addr.into(),
            &self.password,
            map_cipher(&self.cipher)?,
        )
        .map_err(|e| {
            new_io_error(format!("Failed to create Shadowsocks config: {}", e))
        })?;

        // TODO: support multiple users
        let user_manager = shadowsocks::config::ServerUserManager::new();

        config.set_user_manager(user_manager);

        let socket = new_udp_socket(
            Some(self.addr),
            None,
            #[cfg(target_os = "linux")]
            self.fw_mark,
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

        let _ = dispatcher.dispatch_datagram(sess, wrapped_socket).await;
        Ok(())
    }
}
