use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Sink, SinkExt, Stream, StreamExt};
use shadowsocks::ProxySocket;
use tokio::io::ReadBuf;
use tracing::{debug, instrument, trace};

use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::errors::new_io_error,
    proxy::{datagram::UdpPacket, AnyOutboundDatagram},
    session::SocksAddr,
};

/// the outbound datagram for that shadowsocks returns to us
pub struct OutboundDatagramShadowsocks {
    inner: ProxySocket,
    remote_addr: SocksAddr,
    flushed: bool,
    pkt: Option<UdpPacket>,
    buf: Vec<u8>,
    resolver: ThreadSafeDNSResolver,
}

impl OutboundDatagramShadowsocks {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        inner: ProxySocket,
        remote_addr: (String, u16),
        resolver: ThreadSafeDNSResolver,
    ) -> AnyOutboundDatagram {
        let s = Self {
            inner,
            flushed: true,
            pkt: None,
            remote_addr: remote_addr.try_into().expect("must into socks addr"),
            buf: vec![0u8; 65535],
            resolver,
        };
        Box::new(s) as _
    }
}

impl Sink<UdpPacket> for OutboundDatagramShadowsocks {
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

    #[instrument(skip(self, cx))]
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
            ref remote_addr,
            ref mut flushed,
            ref mut resolver,
            ..
        } = *self;

        let dst = match remote_addr.to_owned() {
            SocksAddr::Domain(domain, port) => {
                let domain = domain.to_string();
                let port = port.to_owned();

                let mut fut = resolver.resolve(domain.as_str(), false);
                let ip = ready!(fut.as_mut().poll(cx).map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "resolve domain failed")
                }))?;

                if let Some(ip) = ip {
                    trace!("resolve domain {} to {}", domain, ip);
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

        let pkt_container = pkt;

        if let Some(pkt) = pkt_container {
            let data = pkt.data.as_ref();
            let addr: shadowsocks::relay::Address =
                (pkt.dst_addr.host(), pkt.dst_addr.port()).into();

            let n = ready!(inner.poll_send_to(dst, &addr, data, cx))?;

            debug!(
                "send udp packet to remote ss server, len: {}, remote_addr: {}, \
                 dst_addr: {}",
                n, dst, addr
            );

            let wrote_all = n == data.len();
            *pkt_container = None;
            *flushed = true;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(new_io_error(format!(
                    "failed to write entire datagram, written: {}",
                    n
                )))
            };
            Poll::Ready(res)
        } else {
            debug!("no udp packet to send");
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

impl Stream for OutboundDatagramShadowsocks {
    type Item = UdpPacket;

    #[instrument(skip(self, cx))]
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut buf,
            ref inner,
            ..
        } = *self;

        let mut buf = ReadBuf::new(buf);

        let rv = ready!(inner.poll_recv_from(cx, &mut buf));
        debug!("recv udp packet from remote ss server: {:?}", rv);

        match rv {
            Ok((n, src, ..)) => Poll::Ready(Some(UdpPacket {
                data: buf.filled()[..n].to_vec(),
                src_addr: src.into(),
                dst_addr: SocksAddr::any_ipv4(),
            })),
            Err(_) => Poll::Ready(None),
        }
    }
}

/// Shadowsocks UDP I/O that is passed to shadowsocks relay
pub(crate) struct ShadowsocksUdpIo {
    inner: AnyOutboundDatagram,
}

impl ShadowsocksUdpIo {
    pub fn new(inner: AnyOutboundDatagram) -> Self {
        Self { inner }
    }
}

impl Sink<shadowsocks::relay::udprelay::proxy_socket::UdpPacket>
    for ShadowsocksUdpIo
{
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: shadowsocks::relay::udprelay::proxy_socket::UdpPacket,
    ) -> Result<(), Self::Error> {
        self.inner.start_send_unpin(UdpPacket {
            data: item.data.to_vec(),
            src_addr: item.src.map(|x| x.into()).unwrap_or_default(),
            dst_addr: item.dst.map(|x| x.into()).unwrap_or_default(),
        })
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx)
    }
}

impl Stream for ShadowsocksUdpIo {
    type Item = shadowsocks::relay::udprelay::proxy_socket::UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match ready!(self.inner.poll_next_unpin(cx)) {
            Some(pkt) => {
                let (src, dst) = (
                    pkt.src_addr.must_into_socket_addr(),
                    pkt.dst_addr.must_into_socket_addr(),
                );
                Poll::Ready(Some(
                    shadowsocks::relay::udprelay::proxy_socket::UdpPacket {
                        data: pkt.data.into(),
                        src: src.into(),
                        dst: dst.into(),
                    },
                ))
            }
            None => Poll::Ready(None),
        }
    }
}
