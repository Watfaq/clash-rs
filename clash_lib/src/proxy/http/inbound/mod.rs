mod auth;
mod connector;
mod proxy;

use crate::{
    common::auth::ThreadSafeAuthenticator,
    proxy::{utils::apply_tcp_options, InboundHandler},
    Dispatcher,
};
use async_trait::async_trait;

pub use proxy::handle as handle_http;

use std::{io, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::warn;

#[derive(Clone)]
pub struct Listener {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
}

impl Drop for Listener {
    fn drop(&mut self) {
        warn!("HTTP inbound listener on {} stopped", self.addr);
    }
}

impl Listener {
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

#[async_trait]
impl InboundHandler for Listener {
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

            let socket = apply_tcp_options(socket)?;

            let dispatcher = self.dispatcher.clone();
            let author = self.authenticator.clone();

            tokio::spawn(async move {
                proxy::handle(Box::new(socket), src_addr, dispatcher, author).await
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "unsupported"))
    }
}
