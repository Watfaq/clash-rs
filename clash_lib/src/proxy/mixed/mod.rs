use crate::{
    common::auth::ThreadSafeAuthenticator,
    session::{Network, Session},
    Dispatcher,
};

use std::{net::SocketAddr, sync::Arc};

use tokio::net::TcpListener;
use tracing::warn;

use super::{http, inbound::InboundHandlerTrait, socks, utils::apply_tcp_options};

pub struct MixedInbound {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
}

impl Drop for MixedInbound {
    fn drop(&mut self) {
        warn!("MixedPort inbound listener on {} stopped", self.addr);
    }
}

impl MixedInbound {
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

impl InboundHandlerTrait for MixedInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;

        loop {
            let (socket, _) = listener.accept().await?;
            let socket = apply_tcp_options(socket)?;

            let mut p = [0; 1];
            let n = socket.peek(&mut p).await?;
            if n != 1 {
                warn!("failed to peek socket on mixed listener {}", self.addr);
                continue;
            }

            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();

            match p[0] {
                socks::SOCKS5_VERSION => {
                    let mut sess = Session {
                        network: Network::Tcp,
                        source: socket.peer_addr()?,

                        ..Default::default()
                    };

                    tokio::spawn(async move {
                        socks::handle_tcp(
                            &mut sess,
                            socket,
                            dispatcher,
                            authenticator,
                        )
                        .await
                    });
                }

                _ => {
                    let src = socket.peer_addr()?;
                    http::handle_http(
                        Box::new(socket),
                        src,
                        dispatcher,
                        authenticator,
                    )
                    .await;
                }
            }
        }
    }

    async fn listen_udp(&self) -> anyhow::Result<()> {
        Err(anyhow!("UDP is not supported"))
    }
}
