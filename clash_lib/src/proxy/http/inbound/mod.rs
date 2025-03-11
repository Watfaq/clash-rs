mod auth;
mod connector;
mod proxy;

use crate::{
    Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    proxy::{inbound::AbstractInboundHandler, utils::apply_tcp_options},
};
pub use proxy::handle as handle_http;
use watfaq_error::Result;

use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::warn;

#[derive(Clone)]
pub struct HttpInbound {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
}

impl Drop for HttpInbound {
    fn drop(&mut self) {
        warn!("HTTP inbound listener on {} stopped", self.addr);
    }
}

impl HttpInbound {
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

impl AbstractInboundHandler for HttpInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> Result<()> {
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

    async fn listen_udp(&self) -> Result<()> {
        Err(anyhow!("unsupported"))
    }
}
