use crate::proxy::{AnyInboundListener, InboundListener};
use crate::session::{Network, Session};
use crate::Dispatcher;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::warn;

use super::utils::apply_tcp_options;
use super::{http, socks};

pub struct Listener {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        warn!("MixedPort inbound listener on {} stopped", self.addr);
    }
}

impl Listener {
    pub fn new(addr: SocketAddr, dispatcher: Arc<Dispatcher>) -> AnyInboundListener {
        Arc::new(Self { addr, dispatcher }) as _
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
            let mut socket = apply_tcp_options(socket).await?;

            let mut p = [0; 1];
            let n = socket.peek(&mut p).await?;
            if n != 1 {
                warn!("failed to peek socket on mixed listener {}", self.addr);
                continue;
            }

            match p[0] {
                socks::SOCKS5_VERSION => {
                    let mut sess = Session {
                        network: Network::Tcp,
                        source: socket.peer_addr()?,

                        ..Default::default()
                    };

                    let dispatcher = self.dispatcher.clone();

                    tokio::spawn(async move {
                        socks::handle_tcp(&mut sess, &mut socket, dispatcher, &HashMap::new() as _)
                            .await
                    });
                }

                _ => {
                    let src = socket.peer_addr()?;
                    http::handle_http(Box::new(socket), src, self.dispatcher.clone()).await;
                }
            }
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        unreachable!("don't listen to me :)")
    }
}
