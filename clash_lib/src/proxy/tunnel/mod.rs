use std::{
    io,
    net::SocketAddr,
    ops::DerefMut,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};

use crate::{
    app::dispatcher::Dispatcher,
    session::{Network, Session, TargetAddr, Type},
};
use futures::{Sink, Stream};
use tokio::{
    io::ReadBuf,
    net::{TcpListener, UdpSocket},
};
use tracing::{info, warn};
use watfaq_error::Result;

use super::{
    datagram::UdpPacket, inbound::AbstractInboundHandler, utils::apply_tcp_options,
};

#[derive(Clone)]
pub struct TunnelInbound {
    listen: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    network: Vec<String>,
    target: TargetAddr,
}

impl Drop for TunnelInbound {
    fn drop(&mut self) {
        warn!("Tunnel inbound listener on {} stopped", self.listen);
    }
}

impl TunnelInbound {
    pub fn new(
        addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
        network: Vec<String>,
        target: String,
    ) -> Result<Self> {
        Ok(Self {
            listen: addr,
            dispatcher,
            network,
            target: TargetAddr::from_str(&target)?,
        })
    }
}

impl AbstractInboundHandler for TunnelInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        true
    }

    async fn listen_tcp(&self) -> Result<()> {
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
                network: Network::TCP,
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

    async fn listen_udp(&self) -> Result<()> {
        if !self.network.contains(&"udp".to_string()) {
            return Ok(());
        }
        info!(
            "[Tunnel-UDP] listening on {}, remote: {}",
            self.listen, self.target
        );
        let socket = UdpSocket::bind(self.listen).await?;
        let sess = Session {
            network: Network::UDP,
            typ: Type::Tunnel,
            destination: self.target.clone(),
            ..Default::default()
        };
        let inbound = UdpSession::new(socket, self.target.clone());

        _ = self
            .dispatcher
            .dispatch_datagram(sess, Box::new(inbound))
            .await;
        Ok(())
    }
}

#[derive(Debug)]
struct UdpSession {
    pub socket: UdpSocket,
    pub dst_addr: TargetAddr,
    pub read_buf: Vec<u8>,
    pub send_buf: Option<(Vec<u8>, SocketAddr)>,
}

impl UdpSession {
    fn new(socket: UdpSocket, dst_addr: TargetAddr) -> Self {
        Self {
            socket,
            dst_addr,
            read_buf: Vec::with_capacity(65507),
            send_buf: None,
        }
    }
}

impl Sink<UdpPacket> for UdpSession {
    type Error = watfaq_error::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        let this = self.deref_mut();
        // "Back pressure" mechanism, new data is allowed to be written only when the
        // buffer is empty
        match this.send_buf {
            Some(_) => Poll::Pending,
            None => Poll::Ready(Ok(())),
        }
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<()> {
        let this = self.deref_mut();
        let socket = &this.socket;
        let dst_addr = match item.dst_addr {
            TargetAddr::Socket(socket_addr) => socket_addr,
            TargetAddr::Domain(..) => {
                return Err(anyhow!("UdpPacket dst_src MUSTBE IpAddr instead of Domain"));
            }
        };

        // Try to send immediately, if blocked, enter the buffer and wait for
        // poll_flush to process
        match socket.try_send_to(&item.data, dst_addr) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                this.send_buf = Some((item.data, dst_addr));
                Ok(())
            }
            Err(e) => Err(anyhow!(e)),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        let this = self.deref_mut();
        let socket = &this.socket;
        let send_buf = &this.send_buf;
        if let Some((data, dst_addr)) = send_buf {
            return match socket.try_send_to(data, *dst_addr) {
                Ok(_) => {
                    this.send_buf.take();
                    Poll::Ready(Ok(()))
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Register Waker to wake up when the socket is writable
                    socket.poll_send_ready(cx).map_err(|e| anyhow!(e))
                }
                Err(e) => Poll::Ready(Err(e.into())),
            };
        }
        // No data needs flush
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for UdpSession {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.deref_mut();
        let socket = &this.socket;
        this.read_buf.resize(this.read_buf.capacity(), 0);
        let mut buf = ReadBuf::new(&mut this.read_buf);
        dbg!(buf.initialized().len());
        buf.clear();
        match socket.poll_recv_from(cx, &mut buf) {
            Poll::Ready(Ok(src_addr)) => {
                let data = buf.filled().to_vec();
                let dst_addr = this.dst_addr.clone();
                let src_addr = TargetAddr::from(src_addr);
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr,
                    dst_addr,
                }))
            }
            Poll::Ready(Err(e)) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    Poll::Pending
                } else {
                    // FIXME
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
