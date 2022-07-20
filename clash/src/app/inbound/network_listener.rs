use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::{NatManager, UdpPacket};
use crate::config::internal::config::BindAddress;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::proxy::datagram::SimpleInboundDatagram;
use crate::proxy::{AnyInboundDatagram, AnyInboundHandler, AnyInboundTransport, ProxyError};
use crate::session::{Network, Session, SocksAddr};

pub struct NetworkInboundListener {
    pub bind_addr: BindAddress,
    pub handler: AnyInboundHandler,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
}

pub type Runner = futures::future::BoxFuture<'static, ()>;

impl NetworkInboundListener {
    pub fn listen(&self) -> anyhow::Result<Vec<Runner>> {
        let mut runners = Vec::<Runner>::new();
        let listen_addr = &self.bind_addr;
        if self.handler.stream().is_ok() {
            let listen_addr_cloned = listen_addr.clone();
            let handler_cloned = self.handler.clone();
            let dispatcher_cloned = self.dispatcher.clone();
            let nat_manager_cloned = self.nat_manager.clone();

            runners.push(Box::pin(async move {
                if let Err(e) = handle_tcp_listen(
                    listen_addr_cloned,
                    handler_cloned,
                    dispatcher_cloned,
                    nat_manager_cloned,
                )
                .await
                {
                    log::warn!("handler tcp listen failed: {}", e);
                }
            }));
        }

        if self.handler.datagram().is_ok() {
            let listen_addr_cloned = listen_addr.clone();
            let handler_cloned = self.handler.clone();
            let dispatcher_cloned = self.dispatcher.clone();
            let nat_manager_cloned = self.nat_manager.clone();
            runners.push(Box::pin(async move {
                if let Err(e) = handle_udp_listen(
                    listen_addr_cloned,
                    handler_cloned,
                    dispatcher_cloned,
                    nat_manager_cloned,
                )
                .await
                {
                    log::warn!("handler udp listen failed: {}", e);
                }
            }));
        }

        Ok(runners)
    }
}

async fn handle_tcp_listen(
    listen_addr: BindAddress,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> io::Result<()> {
    let listener = match listen_addr {
        BindAddress::Any => todo!(),
        BindAddress::One(addr) => TcpListener::bind(addr).await?,
    };
    loop {
        let (stream, _) = listener.accept().await?;
        let handler_cloned = handler.clone();
        let dispatcher_cloned = dispatcher.clone();
        let nat_manager_cloned = nat_manager.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_inbound_tcp_stream(
                stream,
                handler_cloned,
                dispatcher_cloned,
                nat_manager_cloned,
            )
            .await
            {}
        });
    }
}

async fn handle_inbound_tcp_stream(
    stream: TcpStream,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> io::Result<()> {
    let source = stream.peer_addr()?;
    let local_addr = stream.local_addr()?;
    let sess = Session {
        network: Network::Tcp,
        source,
        local_addr,
        ..Default::default()
    };
    let transport = handler.stream()?.handle(sess, Box::new(stream)).await?;
    handle_inbound_transport(transport, handler, dispatcher, nat_manager).await;
    Ok(())
}

async fn handle_inbound_transport(
    transport: AnyInboundTransport,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) {
    match transport {
        AnyInboundTransport::Stream(stream, sess) => {
            dispatcher.dispatch_stream(sess, stream).await;
        }
        AnyInboundTransport::Datagram(socket, sess) => {
            handle_inbound_datagram(socket, sess, nat_manager).await
        }
        _ => (),
    }
}

async fn handle_inbound_datagram(
    socket: AnyInboundDatagram,
    sess: Option<Session>,
    nat_manager: Arc<NatManager>,
) {
    let (mut lr, mut ls) = socket.split();

    let (l_tx, mut l_rx): (Sender<UdpPacket>, Receiver<UdpPacket>) =
        tokio::sync::mpsc::channel(100);

    tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            if let Ok(dst_addr) = pkt.dst_addr.try_into() {
                if let Err(e) = ls.send_to(&pkt.data[..], &pkt.src_addr, &dst_addr).await {
                    break;
                }
            } else {
                break;
            }
        }
    });

    let mut buf = vec![0u8; 1500 * 2]; // double MTU
    loop {
        match lr.recv_from(&mut buf).await {
            Err(ProxyError::DatagramFatal(e)) => break,
            Err(ProxyError::DatagramWarn(e)) => continue,
            Ok((n, dgram_src, dst_addr)) => {
                let pkt = UdpPacket::new(
                    buf[..n].to_vec(),
                    SocksAddr::from(dgram_src.address),
                    dst_addr,
                );
                nat_manager
                    .send(sess.as_ref(), &dgram_src, &l_tx, pkt)
                    .await;
            }
        }
    }
}

async fn handle_udp_listen(
    listen_addr: BindAddress,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> io::Result<()> {
    let socket = match listen_addr {
        BindAddress::Any => todo!("bind all not implemented"),
        BindAddress::One(addr) => UdpSocket::bind(&addr).await?,
    };

    let transport = handler
        .datagram()?
        .handle(Box::new(SimpleInboundDatagram(socket)))
        .await?;
    handle_inbound_transport(transport, handler, dispatcher, nat_manager).await;
    Ok(())
}
