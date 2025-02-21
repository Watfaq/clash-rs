use std::{io, net::SocketAddr, ops::DerefMut, pin::Pin, str::FromStr, sync::Arc, task::{Context, Poll}};

use crate::{
    app::dispatcher::Dispatcher, common::errors::new_io_error, session::{Network, Session, SocksAddr, Type}
};
use futures::{Sink, Stream};
use tokio::{io::ReadBuf, net::{TcpListener, UdpSocket}};
use tracing::{info, warn};

use super::{datagram::UdpPacket, inbound::InboundHandlerTrait, utils::apply_tcp_options};

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
        info!("[Tunnel-TCP] listening on {}, remote: {}", self.listen, self.target);
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
        info!("[Tunnel-UDP] listening on {}, remote: {}", self.listen, self.target);
        let socket = UdpSocket::bind(self.listen).await?;
        let sess = Session {
            network: Network::Udp,
            typ: Type::Tunnel,
            destination: self.target.clone(),
            ..Default::default()
        };
        let inbound = UdpSession::new(socket, self.target.clone());

        _ = self.dispatcher.dispatch_datagram(sess, Box::new(inbound)).await;
        Ok(())
    }
}

#[derive(Debug)]
struct UdpSession{
    pub socket: UdpSocket,
    pub dst_addr: SocksAddr,
    pub read_buf: Vec<u8>,
    pub send_buf: Option<(Vec<u8>, SocketAddr)>
}

impl UdpSession {
    fn new(socket:UdpSocket, dst_addr: SocksAddr) -> Self {
        Self {
            socket,
            dst_addr,
            read_buf: Vec::with_capacity(64000),
            send_buf: None
        }
    }
}


impl Sink<UdpPacket> for UdpSession {
    type Error = io::Error;

    fn start_send(mut self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {

        let this = self.deref_mut();

        let dst_addr = match item.dst_addr {
            SocksAddr::Ip(socket_addr) => socket_addr,
            SocksAddr::Domain(_, _) => return Err(new_io_error("UdpPacket dst_src MUSTBE IpAddr instead of Domain")),
        };
        // 将数据包和地址存入缓冲区
        // 不立即尝试发送，等待 poll_flush 处理
        this.send_buf = Some((item.data, dst_addr));
        Ok(())

    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.deref_mut();
        let socket = &this.socket;
        let send_buf = this.send_buf.take();
        if let Some((data, dst_addr)) = send_buf {
            return match socket.try_send_to(&data, dst_addr) {
                Ok(_) => Poll::Ready(Ok(())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // 注册 Waker 以便在 socket 可写时唤醒
                    socket.poll_send_ready(cx)
                },
                Err(e) => Poll::Ready(Err(e)),
            }
        }
        // 无数据需要刷新
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_ready(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.deref_mut();
        // "背压"机制，只有缓冲区为空时才允许新数据写入
        match this.send_buf {
            Some(_) => Poll::Pending,
            None => Poll::Ready(Ok(())),
        }
    }
}

impl Stream for UdpSession {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this  = self.deref_mut();
        let socket = &this.socket;
        let buf = &mut this.read_buf;
        let mut buf = ReadBuf::new(buf);
        buf.clear();
        match socket.poll_recv_from(cx, &mut buf) {
            Poll::Ready(Ok(src_addr)) => {
                let data = buf.filled().to_vec();
                let dst_addr = this.dst_addr.clone();
                let src_addr = SocksAddr::from(src_addr);
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr,
                    dst_addr,
                }))
            }
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

