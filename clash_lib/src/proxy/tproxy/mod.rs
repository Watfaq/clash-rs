use super::tun::TunDatagram;
use crate::{
    app::dispatcher::Dispatcher,
    proxy::{datagram::UdpPacket, utils::apply_tcp_options, InboundListener},
    session::{Network, Session, Type},
};
use async_trait::async_trait;
use socket2::{Domain, Socket};
use std::{
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd},
    sync::Arc,
};
use tokio::net::TcpListener;
use tracing::{trace, warn};

pub struct Listener {
    addr: SocketAddr,
    dispather: Arc<Dispatcher>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        warn!("Tproxy inbound listener on {} stopped", self.addr);
    }
}

impl Listener {
    pub fn new(addr: SocketAddr, dispather: Arc<Dispatcher>) -> Self {
        Self { addr, dispather }
    }
}

#[async_trait]
impl InboundListener for Listener {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        true
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let socket =
            Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        socket.set_ip_transparent(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&self.addr.into())?;
        socket.listen(1024)?;

        let listener = TcpListener::from_std(socket.into())?;

        loop {
            let (socket, src_addr) = listener.accept().await?;

            let socket = apply_tcp_options(socket)?;

            // local_addr is getsockname
            let orig_dst = socket.local_addr()?;

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Tproxy,
                source: src_addr,
                destination: orig_dst.into(),
                ..Default::default()
            };

            trace!("tproxy new tcp conn {}", sess);

            let dispatcher = self.dispather.clone();
            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, socket).await;
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        let socket = Socket::new(Domain::IPV4, socket2::Type::DGRAM, None)?;
        socket.set_ip_transparent(true)?;
        socket.set_nonblocking(true)?;
        socket.set_broadcast(true)?;

        let enable = 1u32;
        let payload = std::ptr::addr_of!(enable).cast();
        unsafe {
            libc::setsockopt(
                socket.as_fd().as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_RECVORIGDSTADDR,
                payload,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };
        socket.bind(&self.addr.into())?;

        let listener = unix_udp_sock::UdpSocket::from_std(socket.into())?;

        handle_inbound_datagram(Arc::new(listener), self.dispather.clone()).await
    }
}

async fn handle_inbound_datagram(
    socket: Arc<unix_udp_sock::UdpSocket>,
    dispatcher: Arc<Dispatcher>,
) -> std::io::Result<()> {
    // dispatcher <-> tproxy communications
    let (l_tx, mut l_rx) = tokio::sync::mpsc::channel(32);

    // forward packets from tproxy to dispatcher
    let (d_tx, d_rx) = tokio::sync::mpsc::channel(32);

    // for dispatcher - the dispatcher would receive packets from this channel,
    // which is from the stack and send back packets to this channel, which is
    // to the tproxy
    let udp_stream = TunDatagram::new(l_tx, d_rx);

    let sess = Session {
        network: Network::Udp,
        typ: Type::Tproxy,
        ..Default::default()
    };

    let closer = dispatcher
        .dispatch_datagram(sess, Box::new(udp_stream))
        .await;

    // dispatcher -> tproxy
    let responder = socket.clone();
    let fut1 = tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            trace!("tproxy <- dispatcher: {:?}", pkt);

            // remote -> local
            match responder
                .send_to(&pkt.data[..], pkt.dst_addr.must_into_socket_addr())
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    warn!("failed to send udp packet to proxy: {}", e);
                }
            }
        }
    });

    // tproxy -> dispatcher
    let fut2 = tokio::spawn(async move {
        let mut buf = vec![0_u8; 1024 * 64];
        while let Ok(meta) = socket.recv_msg(&mut buf).await {
            match meta.orig_dst {
                Some(orig_dst) => {
                    if orig_dst.ip().is_multicast()
                        || match orig_dst.ip() {
                            std::net::IpAddr::V4(ip) => ip.is_broadcast(),
                            std::net::IpAddr::V6(_) => false,
                        }
                    {
                        continue;
                    }

                    trace!("recv msg:{:?} orig_dst:{:?}", meta, orig_dst);
                    let pkt = UdpPacket {
                        data: buf[..meta.len].to_vec(),
                        src_addr: meta.addr.into(),
                        dst_addr: orig_dst.into(),
                    };
                    trace!("tproxy -> dispatcher: {:?}", pkt);
                    match d_tx.send(pkt).await {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("failed to send udp packet to proxy: {}", e);
                            continue;
                        }
                    }
                }
                None => {
                    warn!("failed to get orig_dst");
                    continue;
                }
            }
        }

        closer.send(0).ok();
    });

    let _ = futures::future::join(fut1, fut2).await;
    Ok(())
}
