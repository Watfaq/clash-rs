use super::{inbound::InboundHandlerTrait, tun::TunDatagram};
use crate::{
    app::dispatcher::Dispatcher,
    proxy::{
        datagram::UdpPacket,
        utils::{ToCanonical, apply_tcp_options, try_create_dualstack_socket},
    },
    session::{Network, Session, Type},
};

use async_trait::async_trait;
use std::{
    io, mem,
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd},
    sync::Arc,
};
use tokio::net::TcpListener;
use tracing::{trace, warn};

pub struct TproxyInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
}

impl Drop for TproxyInbound {
    fn drop(&mut self) {
        warn!("Tproxy inbound listener on {} stopped", self.addr);
    }
}

impl TproxyInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            fw_mark,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for TproxyInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        true
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let (socket, dualstack) =
            try_create_dualstack_socket(self.addr, socket2::Type::STREAM)?;
        if dualstack || self.addr.is_ipv4() {
            // set ipv4 transparent
            // IPV6 doesn't require this
            socket.set_ip_transparent_v4(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&self.addr.into())?;
        socket.listen(1024)?;

        let listener = TcpListener::from_std(socket.into())?;

        loop {
            let (socket, _) = listener.accept().await?;
            let src_addr = socket.peer_addr()?.to_canonical();
            // for dualstack socket src_addr may be ipv4 or ipv6;
            // tcpstream.local_addr() is the proxy destination
            // listener.local_addr() is [::]:port for dualstack
            // No simple way to implement allow lan logic
            // TODO
            // if !self.allow_lan && !src_addr.ip().is_loopback() {
            //     warn!("Connection from {} is not allowed localaddr:{}",
            // src_addr,listener.local_addr()?);     continue;
            // }

            apply_tcp_options(&socket)?;

            // local_addr is getsockname
            let orig_dst = socket.local_addr()?.to_canonical();

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Tproxy,
                source: src_addr,
                destination: orig_dst.into(),
                so_mark: self.fw_mark,
                ..Default::default()
            };

            trace!("tproxy new tcp conn {}", sess);

            let dispatcher = self.dispatcher.clone();
            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, Box::new(socket)).await;
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        let (socket, dual_stack) =
            try_create_dualstack_socket(self.addr, socket2::Type::DGRAM)?;
        if dual_stack || self.addr.is_ipv4() {
            // set ipv4 transparent
            // IPv6 doesn't require this
            socket.set_ip_transparent_v4(true)?;
        }

        socket.set_nonblocking(true)?;
        socket.set_broadcast(true)?;
        set_ip_recv_orig_dstaddr(
            if self.addr.is_ipv4() {
                libc::IPPROTO_IP
            } else {
                libc::IPPROTO_IPV6
            },
            &socket,
        )?;
        if dual_stack {
            set_ip_recv_orig_dstaddr(libc::IPPROTO_IP, &socket)?;
        }
        socket.bind(&self.addr.into())?;

        let listener = unix_udp_sock::UdpSocket::from_std(socket.into())?;

        handle_inbound_datagram(
            self.allow_lan,
            Arc::new(listener),
            self.dispatcher.clone(),
        )
        .await
    }
}

async fn handle_inbound_datagram(
    allow_lan: bool,
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

                    trace!(
                        "recv msg:{:?} orig_dst:{:?}, local_addr:{:?}",
                        meta,
                        orig_dst,
                        socket.local_addr()
                    );
                    if !allow_lan
                        && let Ok(local_addr) = socket.local_addr()
                        && meta.addr.ip() != local_addr.ip()
                    {
                        warn!("Connection from {} is not allowed", meta.addr);
                        continue;
                    }
                    let pkt = UdpPacket {
                        data: buf[..meta.len].to_vec(),
                        src_addr: meta.addr.to_canonical().into(),
                        dst_addr: orig_dst.to_canonical().into(),
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
                    trace!(
                        "recv msg:{:?} local_addr:{:?}",
                        meta,
                        socket.local_addr()
                    );
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

fn set_ip_recv_orig_dstaddr(
    level: libc::c_int,
    socket: &socket2::Socket,
) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let opt = match level {
        libc::IPPROTO_IP => libc::IP_RECVORIGDSTADDR,
        libc::IPPROTO_IPV6 => libc::IPV6_RECVORIGDSTADDR,
        _ => unreachable!("invalid sockopt level {}", level),
    };

    let enable: libc::c_int = 1;

    unsafe {
        let ret = libc::setsockopt(
            fd,
            level,
            opt,
            &enable as *const _ as *const _,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}
