mod codec;
mod connector;
mod proxy;

use crate::proxy::utils::apply_tcp_options;
use crate::proxy::{AnyInboundListener, InboundListener};
use crate::Dispatcher;
use async_trait::async_trait;

pub use proxy::handle as handle_http;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::warn;

#[derive(Clone)]
pub struct Listener {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        warn!("HTTP inbound listener on {} stopped", self.addr);
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
            let (socket, src_addr) = listener.accept().await?;

            let socket = apply_tcp_options(socket).await?;

            let dispatcher = self.dispatcher.clone();

            tokio::spawn(
                async move { proxy::handle(Box::new(socket), src_addr, dispatcher).await },
            );
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "unsupported"))
    }
}
