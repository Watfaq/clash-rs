use std::{net::SocketAddr, sync::Arc};

use tracing::{trace, warn};

use crate::{
    app::dispatcher::Dispatcher,
    proxy::{
        datagram::UdpPacket, utils::new_transparent_udp_socket, AnyInboundListener, InboundListener,
    },
    session::{get_packet_mark, Network, Session, SocksAddr, Type},
};

use async_trait::async_trait;

use super::{
    iptables::TProxyGuard,
    transparent_socket::{new_tcp_listener, new_udp_listener},
};
use crate::common::tunnel_datagram::TunnelDatagram;

pub struct Listener {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    _guard: TProxyGuard,
}

impl Listener {
    pub fn new(addr: SocketAddr, dispatcher: Arc<Dispatcher>) -> AnyInboundListener {
        let _guard = TProxyGuard::new(
            Default::default(),
            get_packet_mark(),
            addr.port(),
            None,
            None,
        );

        Arc::new(Self {
            addr,
            dispatcher,
            _guard,
        }) as _
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        warn!("tproxy inbound listener on {} stopped", self.addr);
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
        let listener = new_tcp_listener(self.addr)?;
        loop {
            let (socket, _) = listener.accept().await?;
            let dispatcher = self.dispatcher.clone();
            tokio::spawn(async move {
                let source = socket.peer_addr().unwrap();
                let destination = SocksAddr::Ip(socket.local_addr().unwrap());
                let session = crate::session::Session {
                    source,
                    destination,
                    typ: crate::session::Type::TProxy,
                    ..Default::default()
                };
                dispatcher.dispatch_stream(session, socket).await
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        let listener = new_udp_listener(self.addr).await?;

        handle_inbound_datagram(Arc::new(listener), self.dispatcher.clone()).await
    }
}

async fn handle_inbound_datagram(
    socket: Arc<unix_udp_sock::UdpSocket>,
    dispatcher: Arc<Dispatcher>,
) -> std::io::Result<()> {
    // dispatcher <-> tun communications
    let (l_tx, mut l_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

    // forward packets from tun to dispatcher
    let (d_tx, d_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

    // for dispatcher - the dispatcher would receive packets from this channel, which is from the stack
    // and send back packets to this channel, which is to the tun
    let udp_stream = TunnelDatagram::new(l_tx, d_rx);

    let sess = Session {
        network: Network::Udp,
        typ: Type::TProxy,
        ..Default::default()
    };

    let closer = dispatcher.dispatch_datagram(sess, Box::new(udp_stream));

    // dispatcher -> tproxy
    let fut1 = tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            trace!("tproxy <- dispatcher: {:?}", pkt);
            // populate the correct src_addr, though is it necessary?
            let src_addr: SocketAddr = match pkt.src_addr {
                SocksAddr::Ip(ip) => ip,
                SocksAddr::Domain(host, port) => {
                    warn!("unexpected domain address: {}:{:?}", host, port);
                    continue;
                }
            };
            let response_socket =
                match new_transparent_udp_socket(Some(&src_addr), None, Some(0xff)).await {
                    Ok(response_socket) => response_socket,
                    Err(e) => {
                        warn!("failed to create udp socket, err:{:?}", e);
                        continue;
                    }
                };
            // remote -> local
            match response_socket
                .send_to(&pkt.data[..], &pkt.dst_addr.must_into_socket_addr())
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
