use crate::{
    Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    session::{Network, Session},
};

use super::{http, inbound::InboundHandlerTrait, socks, utils::apply_tcp_options};
use crate::common::errors::new_io_error;
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::warn;

pub struct MixedInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
}

impl Drop for MixedInbound {
    fn drop(&mut self) {
        warn!("MixedPort inbound listener on {} stopped", self.addr);
    }
}

impl MixedInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for MixedInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;

        loop {
            let (socket, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("failed to accept socket on {}: {:?}", self.addr, e);
                    continue;
                }
            };
            let src_addr = match socket.peer_addr() {
                Ok(a) => a,
                Err(e) => {
                    warn!("failed to get peer address: {:?}", e);
                    continue;
                }
            };
            if !self.allow_lan && src_addr.ip() != socket.local_addr()?.ip() {
                warn!("Connection from {} is not allowed", src_addr);
                continue;
            }
            apply_tcp_options(&socket)?;

            let mut p = [0; 1];
            let n = match socket.peek(&mut p).await {
                Ok(n) => n,
                Err(e) => {
                    warn!(
                        "failed to peek socket on mixed listener {}: {:?}",
                        self.addr, e
                    );
                    continue;
                }
            };
            if n != 1 {
                warn!("failed to peek socket on mixed listener {}", self.addr);
                continue;
            }

            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();
            let fw_mark = self.fw_mark;

            match p[0] {
                socks::SOCKS5_VERSION => {
                    let mut sess = Session {
                        network: Network::Tcp,
                        source: socket.peer_addr()?,
                        so_mark: fw_mark,
                        ..Default::default()
                    };

                    tokio::spawn(async move {
                        socks::inbound::handle_tcp(
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
                    let dispatcher = dispatcher.clone();
                    let authenticator = authenticator.clone();
                    tokio::spawn(async move {
                        http::handle_http(
                            Box::new(socket),
                            src,
                            dispatcher,
                            authenticator,
                            fw_mark,
                        )
                        .await;
                    });
                }
            }
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(new_io_error("UDP is not supported"))
    }
}
