use crate::{
    common::auth::ThreadSafeAuthenticator,
    proxy::InboundListener,
    session::{Network, Session},
    Dispatcher,
};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};

use tokio::net::TcpListener;
use tracing::warn;

use super::{http, socks, utils::apply_tcp_options};

pub struct Listener {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
}

impl Drop for Listener {
    fn drop(&mut self) {
        warn!("Tproxy inbound listener on {} stopped", self.addr);
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
impl InboundListener for Listener {
    fn handle_tcp(&self) -> bool {
        false
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        unimplemented!("don't listen to me :)")
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        unimplemented!("don't listen to me :)")
    }
}
