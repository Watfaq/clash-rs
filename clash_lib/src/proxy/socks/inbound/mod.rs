mod datagram;
mod stream;

use crate::{
    Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    proxy::{inbound::AbstractInboundHandler, utils::apply_tcp_options},
    session::{Network, Session, Type},
};

use std::{net::SocketAddr, sync::Arc};
pub use stream::handle_tcp;
use tokio::net::TcpListener;
use tracing::warn;
use watfaq_error::Result;

pub use datagram::Socks5UDPCodec;

pub struct SocksInbound {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
}

impl Drop for SocksInbound {
    fn drop(&mut self) {
        warn!("SOCKS5 inbound listener on {} stopped", self.addr);
    }
}

impl SocksInbound {
    pub fn new(
        addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
    ) -> Self {
        Self {
            addr,
            dispatcher,
            authenticator,
        }
    }
}

impl AbstractInboundHandler for SocksInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;

        loop {
            let (socket, _) = listener.accept().await?;

            let socket = apply_tcp_options(socket)?;

            let mut sess = Session {
                network: Network::TCP,
                typ: Type::Socks5,
                source: socket.peer_addr()?,

                ..Default::default()
            };

            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();
            let ctx = self.clone_ctx();
            tokio::spawn(async move {
                handle_tcp(&ctx, &mut sess, socket, dispatcher, authenticator).await
            });
        }
    }

    async fn listen_udp(&self) -> Result<()> {
        // TODO
        Err(anyhow!("UDP is not supported"))
    }
}
