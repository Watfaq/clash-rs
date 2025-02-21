use std::{net::SocketAddr, str::FromStr, sync::Arc};

use crate::{
    app::dispatcher::Dispatcher,
    common::errors::new_io_error,
    session::{Network, Session, SocksAddr, Type},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};
use tracing::{info, warn};

use super::{
    datagram::UdpPacket, inbound::InboundHandlerTrait, utils::apply_tcp_options,
};
mod compat;

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
        if !self.network.contains(&"tcp".to_string()) {
            return Ok(());
        }
        info!(
            "[Tunnel-TCP] listening on {}, remote: {}",
            self.listen, self.target
        );
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
                dispatcher.dispatch_stream(sess, Box::new(stream)).await;
            });
        }
    }

    async fn listen_udp(&self) -> anyhow::Result<()> {
        if !self.network.contains(&"udp".to_string()) {
            return Ok(());
        }
        info!(
            "[Tunnel-UDP] listening on {}, remote: {}",
            self.listen, self.target
        );
        let socket = UdpSocket::bind(self.listen).await?;

        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

        let target = self.target.clone();

        let sess = Session {
            network: Network::Udp,
            typ: Type::Tunnel,
            destination: self.target.clone(),
            ..Default::default()
        };
        let inbound = UdpSession {
            send_tx: tokio_util::sync::PollSender::new(send_tx),
            recv_rx,
        };

        let _signal = self.dispatcher
            .dispatch_datagram(sess, Box::new(inbound))
            .await;

        let mut buf = Vec::with_capacity(1600);

        loop {
            tokio::select! {
                Ok((len, src_addr)) = socket.recv_from(&mut buf) => {
                    let data = buf[..len].to_vec();
                    let pkt = UdpPacket { data, src_addr: src_addr.into(), dst_addr: target.clone() };
                    recv_tx.send(pkt).await.unwrap();
                }
                Some(send) = send_rx.recv() => {
                    match send.dst_addr {
                        SocksAddr::Domain(_, _) => return Err(anyhow!("UdpPacket dst_src MUSTBE IpAddr instead of Domain")),
                        SocksAddr::Ip(socket_addr) => {
                            socket.send_to(&send.data, socket_addr).await.unwrap();
                        },

                    }
                }
            }
        }
    }
}

#[derive(Debug)]
struct UdpSession {
    send_tx: tokio_util::sync::PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
}
