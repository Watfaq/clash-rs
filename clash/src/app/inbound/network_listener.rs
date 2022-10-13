use crate::app::nat_manager::UdpPacket;
use crate::config::internal::config::BindAddress;
use crate::proxy::AnyInboundListener;
use crate::session::{Network, Session, SocksAddr};

use crate::{Dispatcher, Error, NatManager, Runner};
use log::info;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::{Receiver, Sender};

pub struct NetworkInboundListener {
    pub name: String,
    pub bind_addr: BindAddress,
    pub port: u16,
    pub listener: AnyInboundListener,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
}

impl NetworkInboundListener {
    pub fn listen(&self) -> Result<Vec<Runner>, Error> {
        let mut runners = Vec::<Runner>::new();
        let listen_addr = match self.bind_addr {
            BindAddress::Any => todo!(),
            BindAddress::One(ip) => SocketAddr::new(ip, self.port),
        };

        {
            info!("{} TCP listening at: {}", self.name, &listen_addr);
            let dispatcher_cloned = self.dispatcher.clone();
            let listener = self.listener.clone();

            runners.push(Box::pin(async move {
                if let Err(e) = listener.listen_tcp().await {
                    log::warn!("handler tcp listen failed: {}", e);
                }
            }));
        }

        {
            info!("{} UDP listening at: {}", self.name, &listen_addr);
            let dispatcher_cloned = self.dispatcher.clone();
            let nat_manager_cloned = self.nat_manager.clone();
            let listener = self.listener.clone();

            runners.push(Box::pin(async move {
                if let Err(e) = listener.listen_udp().await {
                    log::warn!("handler udp listen failed: {}", e);
                }
            }));
        }

        Ok(runners)
    }
}
