use crate::proxy::socks::Socks5UDPCodec;
use crate::proxy::{AnyOutboundDatagram, InboundDatagram};
use crate::session::SocksAddr;
use crate::ThreadSafeDNSResolver;
use bytes::Bytes;
use futures::{ready, Sink, SinkExt, Stream, StreamExt};
use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Mutex, RwLock};
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    pub dst_addr: SocksAddr,
}

impl Debug for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("data", &format_args!("{:x?}", &self.data))
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .finish()
    }
}

impl Display for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP Packet from {} to {} with {} bytes",
            self.src_addr,
            self.dst_addr,
            self.data.len()
        )
    }
}

impl UdpPacket {
    pub fn new(data: Vec<u8>, src_addr: SocksAddr, dst_addr: SocksAddr) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
        }
    }
}

pub struct InboundUdp<I> {
    inner: Mutex<I>,
}

impl<I> InboundUdp<I>
where
    I: Stream + Unpin,
    I: Sink<((Bytes, SocksAddr), SocketAddr)>,
{
    pub fn new(inner: I) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }
}

impl Debug for InboundUdp<UdpFramed<Socks5UDPCodec>> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundUdp").finish()
    }
}

impl Stream for InboundUdp<UdpFramed<Socks5UDPCodec>> {
    type Item = UdpPacket;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();
        match pin.inner.try_lock() {
            Ok(mut guard) => match guard.poll_next_unpin(cx) {
                Poll::Ready(item) => match item {
                    None => Poll::Ready(None),
                    Some(item) => match item {
                        Ok(((dst, pkt), src)) => Poll::Ready(Some(UdpPacket {
                            data: pkt.to_vec(),
                            src_addr: SocksAddr::Ip(src),
                            dst_addr: dst,
                        })),
                        Err(_) => Poll::Ready(None),
                    },
                },
                Poll::Pending => Poll::Pending,
            },
            Err(err) => match err {
                std::sync::TryLockError::WouldBlock => Poll::Pending,
                std::sync::TryLockError::Poisoned(_) => Poll::Ready(None),
            },
        }
    }
}

impl Sink<UdpPacket> for InboundUdp<UdpFramed<Socks5UDPCodec>> {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.lock().expect("lock error").poll_ready_unpin(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.inner.lock().expect("lock error").start_send_unpin((
            (item.data.into(), item.src_addr),
            item.dst_addr.must_into_socket_addr(),
        ))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.lock().expect("lock error").poll_flush_unpin(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.lock().expect("lock error").poll_close_unpin(cx)
    }
}

impl InboundDatagram<UdpPacket> for InboundUdp<UdpFramed<Socks5UDPCodec>> {}

#[must_use = "sinks do nothing unless polled"]
pub struct OutboundDatagramImpl {
    inner: RwLock<UdpSocket>,
    resolver: ThreadSafeDNSResolver,
    flushed: bool,
    pkt: Option<UdpPacket>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: ThreadSafeDNSResolver) -> AnyOutboundDatagram {
        let s = Self {
            inner: RwLock::new(udp),
            resolver,
            flushed: true,
            pkt: None,
        };
        Box::new(s) as _
    }
}

impl Sink<UdpPacket> for OutboundDatagramImpl {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            ref mut pkt,
            ref resolver,
            ..
        } = *self;

        if let Some(pkt) = pkt.take() {
            let dst = pkt.dst_addr;
            let data = pkt.data;
            let dst = match dst {
                SocksAddr::Domain(domain, port) => {
                    let domain = domain.to_string();
                    let port = port as u16;
                    let mut fut = resolver.resolve(domain.as_str(), false);
                    let ip = ready!(fut.as_mut().poll(cx).map_err(|_| {
                        io::Error::new(io::ErrorKind::Other, "resolve domain failed")
                    }))?;
                    if let Some(ip) = ip {
                        (ip, port).into()
                    } else {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("resolve domain failed: {}", domain),
                        )));
                    }
                }
                SocksAddr::Ip(addr) => addr,
            };

            let n =
                ready!(inner
                    .write()
                    .expect("lock error")
                    .poll_send_to(cx, data.as_slice(), dst))?;
            let wrote_all = n == data.len();
            self.pkt = None;
            self.flushed = true;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "failed to write entire datagram",
                ))
            };
            Poll::Ready(res)
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "no packet to send",
            )))
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}
impl Stream for OutboundDatagramImpl {
    type Item = UdpPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self { ref mut inner, .. } = *self;
        let mut mem = vec![0u8; 65535];
        let mut buf = ReadBuf::new(&mut mem);
        match ready!(inner
            .read()
            .expect("lock error")
            .poll_recv_from(cx, &mut buf))
        {
            Ok(src) => {
                let data = buf.filled().to_vec();
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr: src.into(),
                    dst_addr: SocksAddr::any_ipv4(),
                }))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}
