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

/// Resolve a domain name to a socket address, preferring IPv4 when the local
/// socket is IPv4.  Returns `Poll::Pending` while the DNS future is pending.
fn resolve_domain(
    domain: &str,
    port: u16,
    is_ipv6: bool,
    resolver: &ThreadSafeDNSResolver,
    cx: &mut Context<'_>,
) -> Poll<io::Result<SocketAddr>> {
    let mut fut = if is_ipv6 {
        resolver.resolve(domain, false)
    } else {
        resolver
            .resolve_v4(domain, false)
            .map(|x| x.map(|ip| ip.map(Into::into)))
            .boxed()
    };
    let ip = ready!(
        fut.as_mut()
            .poll(cx)
            .map_err(|_| io::Error::other("resolve domain failed"))
    )?;
    match ip {
        Some(ip) => Poll::Ready(Ok(SocketAddr::from((ip, port)))),
        None => Poll::Ready(Err(io::Error::other(format!(
            "resolve domain failed: {domain}"
        )))),
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
    recv_buf: Vec<u8>,
    // real upstream IP → dst_addr of the most recent outgoing packet to that
    // IP; used in poll_next to translate src_addr back to dst_addr.
    ip_to_logical: HashMap<SocketAddr, (SocksAddr, Instant)>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: ThreadSafeDNSResolver) -> Self {
        Self {
            inner: udp,
            resolver,
            flushed: true,
            pkt: None,
            recv_buf: vec![0u8; 65535],
            ip_to_logical: HashMap::new(),
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
            ref mut ip_to_logical,
            ..
        } = *self;

        let p = pkt
            .as_ref()
            .ok_or_else(|| io::Error::other("no packet to send"))?;
        let data = p.data.clone();
        let logical = p.dst_addr.clone();
        let is_ipv6 = inner.local_addr()?.is_ipv6();

        let dst = match logical {
            SocksAddr::Ip(addr) => addr,
            SocksAddr::Domain(ref domain, port) => {
                ready!(resolve_domain(domain, port, is_ipv6, resolver, cx))?
            }
        };

        let n = ready!(inner.poll_send_to(cx, data.as_slice(), dst))?;

        let now = Instant::now();
        ip_to_logical
            .retain(|_, (_, ts)| now.duration_since(*ts) < UDP_DOMAIN_MAP_TTL);
        ip_to_logical.insert(dst, (logical, now));

        *pkt = None;
        self.flushed = true;

        if n == data.len() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(new_io_error(format!(
                "failed to send all data, only sent {n} bytes"
            ))))
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
            ref ip_to_logical,
            ..
        } = *self;
        let mut buf = ReadBuf::new(recv_buf.as_mut_slice());
        match ready!(inner.poll_recv_from(cx, &mut buf)) {
            Ok(src) => {
                let data = buf.filled().to_vec();
                let src_addr = ip_to_logical
                    .get(&src)
                    .map(|(logical, _)| logical.clone())
                    .unwrap_or_else(|| src.into());
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr,
                    dst_addr: SocksAddr::any_ipv4(),
                    ..Default::default()
                }))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}
