use crate::{
    app::dns::ThreadSafeDNSResolver, common::errors::new_io_error,
    proxy::datagram::UdpPacket, session::SocksAddr,
};
use futures::{Sink, Stream, ready};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{io::ReadBuf, net::UdpSocket, task::JoinHandle};

const UDP_DOMAIN_MAP_TTL: Duration = Duration::from_secs(60);

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
    /// In-flight DNS resolution task for the current queued packet.
    /// Using a JoinHandle (Send + Sync) rather than a raw BoxFuture so that
    /// OutboundDatagramImpl satisfies the Sync bound required by
    /// ChainedDatagram. The task is spawned once and awaited across polls —
    /// no query restarts.
    pending_dns: Option<JoinHandle<io::Result<SocketAddr>>>,
    /// Resolved IP for the current queued packet; reused across poll_send_to
    /// retries so we never re-poll an already-completed DNS task.
    resolved_dst: Option<SocketAddr>,
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
            pending_dns: None,
            resolved_dst: None,
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
        if let Some(handle) = pin.pending_dns.take() {
            handle.abort();
        }
        pin.pkt = Some(item);
        pin.flushed = false;
        pin.resolved_dst = None;
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
            ref mut pending_dns,
            ref mut resolved_dst,
            ..
        } = *self;

        let p = pkt
            .as_ref()
            .ok_or_else(|| io::Error::other("no packet to send"))?;

        let dst = match &p.dst_addr {
            SocksAddr::Ip(addr) => {
                // Explicit IP path: clear any stale DNS state from a prior packet.
                *pending_dns = None;
                *resolved_dst = None;
                *addr
            }
            SocksAddr::Domain(domain, port) => {
                if let Some(addr) = *resolved_dst {
                    // Already resolved on a prior poll; skip DNS entirely.
                    addr
                } else {
                    let is_ipv6 = inner.local_addr()?.is_ipv6();
                    let handle = pending_dns.get_or_insert_with(|| {
                        let resolver = resolver.clone();
                        let domain = domain.clone();
                        let port = *port;
                        tokio::spawn(async move {
                            let ip = if is_ipv6 {
                                resolver.resolve(&domain, false).await.map_err(
                                    |_| io::Error::other("resolve domain failed"),
                                )?
                            } else {
                                resolver
                                    .resolve_v4(&domain, false)
                                    .await
                                    .map_err(|_| {
                                        io::Error::other("resolve domain failed")
                                    })?
                                    .map(IpAddr::V4)
                            };
                            match ip {
                                Some(ip) => Ok(SocketAddr::from((ip, port))),
                                None => Err(io::Error::other(format!(
                                    "resolve domain failed: {domain}"
                                ))),
                            }
                        })
                    });
                    let addr = match ready!(Pin::new(handle).poll(cx)) {
                        Ok(result) => result?,
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "DNS task panicked: {e}"
                            ))));
                        }
                    };
                    *pending_dns = None;
                    *resolved_dst = Some(addr);
                    addr
                }
            }
        };

        let n = ready!(inner.poll_send_to(cx, p.data.as_slice(), dst))?;

        let now = Instant::now();
        ip_to_logical
            .retain(|_, (_, ts)| now.duration_since(*ts) < UDP_DOMAIN_MAP_TTL);
        ip_to_logical.insert(dst, (p.dst_addr.clone(), now));
        // Save length before clearing pkt (NLL ends p's borrow after this).
        let data_len = p.data.len();

        *pkt = None;
        self.flushed = true;

        if n == data_len {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::MockClashResolver;
    use futures::{SinkExt, StreamExt};
    use std::{collections::HashSet, net::Ipv4Addr, sync::Arc, time::Duration};
    use tokio::net::UdpSocket;

    /// Spawn a loopback UDP echo server; returns its port.
    async fn spawn_echo_server() -> u16 {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        });
        port
    }

    /// Build an `OutboundDatagramImpl` backed by a loopback socket with a mock
    /// resolver that maps every domain to `127.0.0.1`.
    async fn make_datagram() -> OutboundDatagramImpl {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_v4()
            .returning(|_, _| Ok(Some(Ipv4Addr::LOCALHOST)));
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        OutboundDatagramImpl::new(udp, Arc::new(resolver))
    }

    #[tokio::test]
    async fn test_single_dest_domain_src_addr_restored() {
        let echo_port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let dst = SocksAddr::Domain("echo.test".to_owned(), echo_port);
        datagram
            .send(UdpPacket {
                data: b"hello".to_vec(),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out")
            .expect("stream ended");

        assert_eq!(pkt.src_addr, dst, "src_addr must be restored to the domain");
        assert_eq!(pkt.data, b"hello");
    }

    /// A single outbound socket sends to **two** different domain destinations
    /// (1→N); each response must carry the correct logical src_addr.
    #[tokio::test]
    async fn test_multi_dest_1_to_n_src_addr_restored() {
        let port_a = spawn_echo_server().await;
        let port_b = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let dst_a = SocksAddr::Domain("echo1.test".to_owned(), port_a);
        let dst_b = SocksAddr::Domain("echo2.test".to_owned(), port_b);

        // One socket, two destinations — 1→N.
        datagram
            .send(UdpPacket {
                data: b"to-a".to_vec(),
                dst_addr: dst_a.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        datagram
            .send(UdpPacket {
                data: b"to-b".to_vec(),
                dst_addr: dst_b.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        // Responses may arrive in any order.
        let timeout = Duration::from_secs(2);
        let pkt1 = tokio::time::timeout(timeout, datagram.next())
            .await
            .expect("timed out waiting for first response")
            .expect("stream ended");
        let pkt2 = tokio::time::timeout(timeout, datagram.next())
            .await
            .expect("timed out waiting for second response")
            .expect("stream ended");

        let got: HashSet<SocksAddr> =
            [pkt1.src_addr, pkt2.src_addr].into_iter().collect();
        assert!(got.contains(&dst_a), "missing echo1.test src_addr");
        assert!(got.contains(&dst_b), "missing echo2.test src_addr");
    }

    /// Full-cone NAT: once a mapping exists, **any** remote host can send
    /// inbound packets to the outbound socket and they are forwarded.
    /// The src_addr of an unsolicited packet falls back to the raw IP.
    #[tokio::test]
    async fn test_full_cone_unsolicited_inbound_accepted() {
        let echo_port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        // Read the outbound port before moving `datagram` into the stream.
        let outbound_port = {
            let addr = datagram
                .inner
                .local_addr()
                .expect("local_addr must be available");
            addr.port()
        };

        // Establish a session to the echo server so ip_to_logical is populated.
        let dst = SocksAddr::Domain("echo.test".to_owned(), echo_port);
        datagram
            .send(UdpPacket {
                data: b"establish".to_vec(),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out")
            .expect("stream ended");
        assert_eq!(
            pkt.src_addr, dst,
            "echo response must restore domain src_addr"
        );

        // A third-party socket (absent from ip_to_logical) sends unsolicited.
        let third_party = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let third_party_addr = third_party.local_addr().unwrap();
        third_party
            .send_to(b"unsolicited", ("127.0.0.1", outbound_port))
            .await
            .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out waiting for unsolicited packet")
            .expect("stream ended");

        // Full-cone: the packet is delivered (not dropped).
        assert_eq!(pkt.data, b"unsolicited");
        // src_addr is the raw IP because the sender is not in ip_to_logical.
        assert_eq!(pkt.src_addr, SocksAddr::Ip(third_party_addr));
    }
}
