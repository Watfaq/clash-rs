mod datagram;
mod stream;

use crate::proxy::{AnyInboundListener, InboundListener};
use crate::session::{Network, Session};
use crate::Dispatcher;
use async_trait::async_trait;
use socket2::TcpKeepalive;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stream::handle_tcp;
use tokio::net::{TcpListener, TcpStream};

pub use datagram::Socks5UDPCodec;

pub const SOCKS_VERSION: u8 = 0x05;

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
}

impl Listener {
    pub fn new(addr: SocketAddr, dispatcher: Arc<Dispatcher>) -> AnyInboundListener {
        Arc::new(Self { addr, dispatcher }) as _
    }

    async fn apply_tcp_options(s: TcpStream) -> std::io::Result<TcpStream> {
        let s = socket2::Socket::from(s.into_std()?);
        s.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )?;
        Ok(TcpStream::from_std(s.into())?)
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

            let mut socket = Listener::apply_tcp_options(socket).await?;

            let mut sess = Session {
                network: Network::Tcp,
                source: socket.peer_addr()?,

                ..Default::default()
            };

            let dispatcher = self.dispatcher.clone();

            tokio::spawn(async move {
                handle_tcp(&mut sess, &mut socket, dispatcher, &HashMap::new() as _).await
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        unreachable!("don't listen to me :)")
    }
}
