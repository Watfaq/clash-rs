mod datagram;
mod stream;

use crate::{
    common::auth::ThreadSafeAuthenticator,
    proxy::{utils::apply_tcp_options, AnyInboundListener, InboundListener},
    session::{Network, Session, Type},
    Dispatcher,
};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
pub use stream::handle_tcp;
use tokio::net::TcpListener;
use tracing::warn;

pub use datagram::Socks5UDPCodec;

pub const SOCKS5_VERSION: u8 = 0x05;

pub(crate) mod auth_methods {
    pub const NO_AUTH: u8 = 0x00;
    pub const USER_PASS: u8 = 0x02;
    pub const NO_METHODS: u8 = 0xff;
}

pub(crate) mod response_code {
    pub const SUCCEEDED: u8 = 0x00;
    pub const FAILURE: u8 = 0x01;
    // pub const RULE_FAILURE: u8 = 0x02;
    // pub const NETWORK_UNREACHABLE: u8 = 0x03;
    // pub const HOST_UNREACHABLE: u8 = 0x04;
    // pub const CONNECTION_REFUSED: u8 = 0x05;
    // pub const TTL_EXPIRED: u8 = 0x06;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    // pub const ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

pub(crate) mod socks_command {
    pub const CONNECT: u8 = 0x01;
    // pub const BIND: u8 = 0x02;
    pub const UDP_ASSOCIATE: u8 = 0x3;
}

pub struct Listener {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
}

impl Drop for Listener {
    fn drop(&mut self) {
        warn!("SOCKS5 inbound listener on {} stopped", self.addr);
    }
}

impl Listener {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
    ) -> AnyInboundListener {
        Arc::new(Self {
            addr,
            dispatcher,
            authenticator,
        }) as _
    }
}

#[async_trait]
impl InboundListener for Listener {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;

        loop {
            let (socket, _) = listener.accept().await?;

            let mut socket = apply_tcp_options(socket)?;

            let mut sess = Session {
                network: Network::Tcp,
                typ: Type::Socks5,
                source: socket.peer_addr()?,

                ..Default::default()
            };

            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();

            tokio::spawn(async move {
                handle_tcp(&mut sess, &mut socket, dispatcher, authenticator).await
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        unreachable!("don't listen to me :)")
    }
}
