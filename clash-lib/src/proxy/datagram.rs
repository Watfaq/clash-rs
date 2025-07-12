use crate::{
    app::dns::ThreadSafeDNSResolver, common::errors::new_io_error,
    session::SocksAddr,
};
use futures::{FutureExt, Sink, Stream, ready};
use std::{
    fmt::{Debug, Display, Formatter},
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{io::ReadBuf, net::UdpSocket};

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    pub dst_addr: SocksAddr,
}

impl Default for UdpPacket {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::any_ipv4(),
        }
    }
}

impl Debug for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
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

#[must_use = "sinks do nothing unless polled"]
// TODO: maybe we should use abstract datagram IO interface instead of the
// Stream + Sink trait
pub struct OutboundDatagramImpl {
    inner: UdpSocket,
    resolver: ThreadSafeDNSResolver,
    flushed: bool,
    pkt: Option<UdpPacket>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: ThreadSafeDNSResolver) -> Self {
        Self {
            inner: udp,
            resolver,
            flushed: true,
            pkt: None,
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramImpl {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
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

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            ref mut pkt,
            ref resolver,
            ..
        } = *self;

        if pkt.is_some() {
            let p = pkt.as_ref().unwrap();
            let dst = &p.dst_addr;
            let data = &p.data;
            let dst = match dst {
                SocksAddr::Domain(domain, port) => {
                    let domain = domain.to_string();
                    let port = *port;
                    let mut fut = {
                        if inner.local_addr()?.is_ipv6() {
                            resolver.resolve(domain.as_str(), false)
                        } else {
                            resolver
                                .resolve_v4(domain.as_str(), false)
                                .map(|x| x.map(|ip| ip.map(Into::into)))
                                .boxed()
                        }
                    };
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
                SocksAddr::Ip(addr) => *addr,
            };

            let n = ready!(inner.poll_send_to(cx, data.as_slice(), dst))?;
            let wrote_all = n == data.len();
            self.pkt = None;
            self.flushed = true;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(new_io_error(format!(
                    "failed to send all data, only sent {} bytes",
                    n
                )))
            };
            Poll::Ready(res)
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "no packet to send",
            )))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}
impl Stream for OutboundDatagramImpl {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
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
