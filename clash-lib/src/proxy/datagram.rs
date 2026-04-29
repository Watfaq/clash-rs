use crate::{
    app::dns::ThreadSafeDNSResolver, common::errors::new_io_error,
    session::SocksAddr,
};
use futures::{FutureExt, Sink, Stream, ready};
use std::{
    collections::HashMap,
    fmt::{Debug, Display, Formatter},
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{io::ReadBuf, net::UdpSocket};

const UDP_DOMAIN_MAP_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    pub dst_addr: SocksAddr,
    /// Authenticated user name from SS2022 EIH, propagated to the dispatcher
    /// session for per-user traffic attribution. `None` for all other
    /// protocols.
    pub inbound_user: Option<String>,
}

impl Default for UdpPacket {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::any_ipv4(),
            inbound_user: None,
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
            inbound_user: None,
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
    // Pre-allocated receive buffer; avoids a 65535-byte heap allocation on
    // every poll_next call.
    recv_buf: Vec<u8>,
    // Maps resolved upstream IP addresses back to the domain name that was
    // sent to, so poll_next can restore the logical src_addr. The dispatcher
    // then maps domain → original inbound destination (e.g. fake-IP).
    ip_to_domain: HashMap<SocketAddr, (SocksAddr, Instant)>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: ThreadSafeDNSResolver) -> Self {
        Self {
            inner: udp,
            resolver,
            flushed: true,
            pkt: None,
            recv_buf: vec![0u8; 65535],
            ip_to_domain: HashMap::new(),
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
            ref mut ip_to_domain,
            ..
        } = *self;

        if pkt.is_some() {
            let p = pkt.as_ref().unwrap();
            let orig_dst = p.dst_addr.clone();
            let data = &p.data;
            let dst = match &p.dst_addr {
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
                        io::Error::other("resolve domain failed")
                    }))?;
                    if let Some(ip) = ip {
                        let resolved: SocketAddr = (ip, port).into();
                        // Prune stale entries then record this domain mapping.
                        let now = Instant::now();
                        ip_to_domain.retain(|_, (_, ts)| {
                            now.duration_since(*ts) < UDP_DOMAIN_MAP_TTL
                        });
                        ip_to_domain.insert(resolved, (orig_dst, now));
                        resolved
                    } else {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "resolve domain failed: {domain}"
                        ))));
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
                    "failed to send all data, only sent {n} bytes"
                )))
            };
            Poll::Ready(res)
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
            ref ip_to_domain,
            ..
        } = *self;
        let mut buf = ReadBuf::new(recv_buf.as_mut_slice());
        match ready!(inner.poll_recv_from(cx, &mut buf)) {
            Ok(src) => {
                let data = buf.filled().to_vec();
                // If this upstream IP was resolved from a domain name, restore
                // the domain as src_addr so the dispatcher can map it back to
                // the original fake-IP destination.
                let src_addr = ip_to_domain
                    .get(&src)
                    .map(|(domain_addr, _)| domain_addr.clone())
                    .unwrap_or_else(|| src.into());
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr,
                    dst_addr: SocksAddr::any_ipv4(),
                    inbound_user: None,
                }))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}
