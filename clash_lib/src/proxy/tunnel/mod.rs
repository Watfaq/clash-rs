use std::{net::SocketAddr, str::FromStr, sync::Arc};

use crate::{
    app::dispatcher::Dispatcher,
    session::{Network, Session, SocksAddr, Type},
};
use anyhow::Ok;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::warn;

use super::{inbound::InboundHandlerTrait, utils::apply_tcp_options};

#[derive(Clone)]
pub struct TunnelInbound {
    listen: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    network: Vec<String>,
    target: SocksAddr,
}

impl Drop for TunnelInbound {
    fn drop(&mut self) {
        warn!("HTTP inbound listener on {} stopped", self.listen);
    }
}

impl TunnelInbound {
    pub fn new(
        addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
        network: Vec<String>,
        target: String,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            listen: addr,
            dispatcher,
            network,
            target: SocksAddr::from_str(&target)?,
        })
    }
}

impl InboundHandlerTrait for TunnelInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        true
    }

    async fn listen_tcp(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.listen).await?;

        loop {
            let (socket, src_addr) = listener.accept().await?;

            let stream = apply_tcp_options(socket)?;

            let dispatcher = self.dispatcher.clone();
            let sess = Session {
                network: Network::Tcp,
                typ: Type::Tunnel,
                source: src_addr,
                destination: self.target.clone(),
                ..Default::default()
            };

            tokio::spawn(async move {
                handle_tcp(sess, stream, dispatcher).await;
            });
        }
    }

    async fn listen_udp(&self) -> anyhow::Result<()> {
        let listener = UdpSocket::bind(self.listen).await?;
        unimplemented!()
    }
}

async fn handle_tcp(sess: Session, stream: TcpStream, dispatcher: Arc<Dispatcher>) {
    // dispatcher.dispatch_stream(sess, lhs)
}
