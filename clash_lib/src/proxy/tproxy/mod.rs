use crate::proxy::InboundListener;
use async_trait::async_trait;
use std::net::SocketAddr;

use tracing::warn;

pub struct Listener {
    addr: SocketAddr,
}

impl Drop for Listener {
    fn drop(&mut self) {
        warn!("Tproxy inbound listener on {} stopped", self.addr);
    }
}

impl Listener {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
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
