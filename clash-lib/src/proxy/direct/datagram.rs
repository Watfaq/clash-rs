use crate::{
    app::dns::ThreadSafeDNSResolver, common::errors::new_io_error,
    proxy::datagram::UdpPacket, session::SocksAddr,
};
use futures::{FutureExt, Sink, Stream, ready};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{io::ReadBuf, net::UdpSocket};

const UDP_DOMAIN_MAP_TTL: Duration = Duration::from_secs(60);

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
    // Maps resolved upstream IP addresses back to the original inbound
    // destination (fake-IP or direct IP) so poll_next can restore the correct
    // src_addr for the inbound client.  The value is the original dst_addr
    // from the packet (the fake-IP, or a real IP/domain for non-fake-IP
    // flows).
    ip_to_orig: HashMap<SocketAddr, (SocksAddr, Instant)>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: ThreadSafeDNSResolver) -> Self {
        Self {
            inner: udp,
            resolver,
            flushed: true,
            pkt: None,
            recv_buf: vec![0u8; 65535],
            ip_to_orig: HashMap::new(),
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
            ref mut ip_to_orig,
            ..
        } = *self;

        if pkt.is_some() {
            let p = pkt.as_ref().unwrap();
            // The original inbound destination (fake-IP or real IP).  Stored
            // in ip_to_orig so responses can be stamped with it as src_addr.
            let orig_dst = p.dst_addr.clone();
            let data = &p.data;

            // Determine where to actually send the packet.
            // - If dst_domain is set (always a SocksAddr::Domain), resolve it to a
            //   real IP and map real-IP → orig_dst (the fake-IP) for responses.
            // - If dst_domain is None, dst_addr must be a real IP. Guard against a
            //   fake-IP slipping through without a domain set, which would be a
            //   dispatcher bug (guarded there).
            let dst = match &p.dst_domain {
                Some(domain_addr) => {
                    // Fake-IP (or cache-hit) case: resolve the domain.
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
                        let resolved: SocketAddr = (ip, port).into();
                        // Prune stale entries, then store real-IP → orig_dst.
                        let now = Instant::now();
                        ip_to_orig.retain(|_, (_, ts)| {
                            now.duration_since(*ts) < UDP_DOMAIN_MAP_TTL
                        });
                        ip_to_orig.insert(resolved, (orig_dst, now));
                        resolved
                    } else {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "resolve domain failed: {domain}"
                        ))));
                    }
                }
                None => {
                    // No domain — dst_addr is already the target.
                    match &p.dst_addr {
                        SocksAddr::Ip(addr) => *addr,
                        SocksAddr::Domain(domain, port) => {
                            // SOCKS5 client sent a domain directly (no
                            // fake-IP).  Resolve it; no ip_to_orig entry
                            // needed because orig_dst == Domain (same).
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
                                let resolved: SocketAddr = (ip, port).into();
                                let now = Instant::now();
                                ip_to_orig.retain(|_, (_, ts)| {
                                    now.duration_since(*ts) < UDP_DOMAIN_MAP_TTL
                                });
                                // Map real-IP → Domain addr so the response
                                // src_addr shows the domain, not the raw IP.
                                ip_to_orig.insert(resolved, (orig_dst, now));
                                resolved
                            } else {
                                return Poll::Ready(Err(io::Error::other(format!(
                                    "resolve domain failed: {domain}"
                                ))));
                            }
                        }
                    }
                }
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
            ref ip_to_orig,
            ..
        } = *self;
        let mut buf = ReadBuf::new(recv_buf.as_mut_slice());
        match ready!(inner.poll_recv_from(cx, &mut buf)) {
            Ok(src) => {
                let data = buf.filled().to_vec();
                // Restore the original inbound destination (fake-IP or domain)
                // as src_addr so the client receives it as the reply source.
                let src_addr = ip_to_orig
                    .get(&src)
                    .map(|(orig, _)| orig.clone())
                    .unwrap_or_else(|| src.into());
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr,
                    dst_addr: SocksAddr::any_ipv4(),
                    dst_domain: None,
                    inbound_user: None,
                }))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}
