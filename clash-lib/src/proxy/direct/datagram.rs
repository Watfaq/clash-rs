use crate::{
    app::dns::ThreadSafeDNSResolver, common::errors::new_io_error,
    proxy::datagram::UdpPacket, session::SocksAddr,
};
use futures::{FutureExt, Sink, Stream, ready};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{io::ReadBuf, net::UdpSocket};

#[must_use = "sinks do nothing unless polled"]
// TODO: maybe we should use abstract datagram IO interface instead of the
// Stream + Sink trait
pub struct OutboundDatagramImpl {
    inner: UdpSocket,
    resolver: ThreadSafeDNSResolver,
    flushed: bool,
    pkt: Option<UdpPacket>,
    // Pre-allocated receive buffer; avoids a 65535-byte heap allocation on
    // every poll_next call.
    recv_buf: Vec<u8>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: ThreadSafeDNSResolver) -> Self {
        Self {
            inner: udp,
            resolver,
            flushed: true,
            pkt: None,
            recv_buf: vec![0u8; 65535],
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
            let data = &p.data;

            // Determine the real socket address to send to.
            // If dst_domain is set, resolve it; otherwise use dst_addr
            // directly (already a real IP, or a domain from a SOCKS5 client).
            let dst = match &p.dst_domain {
                Some(domain_addr) => {
                    // Invariant: dst_domain is always a Domain variant when set.
                    let SocksAddr::Domain(domain, port) = domain_addr else {
                        return Poll::Ready(Err(io::Error::other(
                            "dst_domain must be a Domain variant",
                        )));
                    };
                    let (domain, port) = (domain.clone(), *port);
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
                        io::Error::other("resolve domain failed")
                    }))?;
                    if let Some(ip) = ip {
                        SocketAddr::from((ip, port))
                    } else {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "resolve domain failed: {domain}"
                        ))));
                    }
                }
                None => match &p.dst_addr {
                    SocksAddr::Ip(addr) => *addr,
                    SocksAddr::Domain(domain, port) => {
                        let domain = domain.clone();
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
                            io::Error::other("resolve domain failed")
                        }))?;
                        if let Some(ip) = ip {
                            SocketAddr::from((ip, port))
                        } else {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "resolve domain failed: {domain}"
                            ))));
                        }
                    }
                },
            };

            let n = ready!(inner.poll_send_to(cx, data.as_slice(), dst))?;
            let wrote_all = n == data.len();
            self.pkt = None;
            self.flushed = true;

            Poll::Ready(if wrote_all {
                Ok(())
            } else {
                Err(new_io_error(format!(
                    "failed to send all data, only sent {n} bytes"
                )))
            })
        } else {
            Poll::Ready(Err(io::Error::other("no packet to send")))
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
        let Self {
            ref mut inner,
            ref mut recv_buf,
            ..
        } = *self;
        let mut buf = ReadBuf::new(recv_buf.as_mut_slice());
        match ready!(inner.poll_recv_from(cx, &mut buf)) {
            Ok(src) => {
                let data = buf.filled().to_vec();
                // src_addr is the raw upstream socket address; the dispatcher's
                // r_handle will overwrite it with the original fake-IP (or
                // real-IP) via the watch channel.
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr: src.into(),
                    dst_addr: SocksAddr::any_ipv4(),
                    dst_domain: None,
                    inbound_user: None,
                }))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}
