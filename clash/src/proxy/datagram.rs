use crate::proxy::socks::Socks5UDPCodec;
use crate::proxy::{AnyOutboundDatagram, InboundDatagram, ProxyError};
use crate::session::SocksAddr;
use crate::ThreadSafeDNSResolver;
use bytes::Bytes;
use futures::{ready, Sink, Stream};
use pin_project::pin_project;
use std::borrow::Borrow;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    pub dst_addr: SocksAddr,
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

#[pin_project]
pub struct InboundUdp<I> {
    #[pin]
    inner: I,
}

impl<I> InboundUdp<I>
where
    I: Stream + Unpin,
    I: Sink<((Bytes, SocksAddr), SocketAddr)>,
{
    pub fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl Stream for InboundUdp<UdpFramed<Socks5UDPCodec>> {
    type Item = UdpPacket;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().inner.poll_next(cx) {
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
        }
    }
}

impl Sink<UdpPacket> for InboundUdp<UdpFramed<Socks5UDPCodec>> {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        self.project().inner.start_send((
            (item.data.into(), item.dst_addr),
            (
                item.src_addr
                    .ip()
                    .expect("UdpPacket src must be SocketAddr"),
                item.src_addr.port(),
            )
                .into(),
        ))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

impl InboundDatagram<UdpPacket> for InboundUdp<UdpFramed<Socks5UDPCodec>> {}

#[must_use = "sinks do nothing unless polled"]
pub struct OutboundDatagramImpl {
    inner: UdpSocket,
    resolver: ThreadSafeDNSResolver,
    flushed: bool,
    pkt: Option<UdpPacket>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: ThreadSafeDNSResolver) -> AnyOutboundDatagram {
        let s = Self {
            inner: udp,
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
                    let resolver = resolver.clone();
                    let guard = resolver.blocking_read();
                    let mut fut = guard.resolve(domain.as_str());
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

            let n = ready!(inner.poll_send_to(cx, data.as_slice(), dst))?;
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
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        todo!()
    }
}
impl Stream for OutboundDatagramImpl {
    type Item = UdpPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self { ref mut inner, .. } = *self;
        let mut mem = vec![0u8; 65535];
        let mut buf = ReadBuf::new(&mut mem);
        match ready!(inner.poll_recv_from(cx, &mut buf)) {
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
