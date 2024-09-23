use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures::{
    ready,
    stream::{SplitSink, SplitStream},
    Sink, SinkExt, Stream, StreamExt,
};
use shadowsocks::{
    relay::udprelay::{DatagramReceive, DatagramSend},
    ProxySocket,
};
use tokio::io::ReadBuf;
use tracing::{debug, instrument, trace};

use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::errors::new_io_error,
    proxy::{datagram::UdpPacket, AnyOutboundDatagram},
    session::SocksAddr,
};

/// the outbound datagram for that shadowsocks returns to us
pub struct OutboundDatagramShadowsocks<S> {
    inner: ProxySocket<S>,
    remote_addr: SocksAddr,
    flushed: bool,
    pkt: Option<UdpPacket>,
    buf: Vec<u8>,
    resolver: ThreadSafeDNSResolver,
}

impl<S> OutboundDatagramShadowsocks<S> {
    pub fn new(
        inner: ProxySocket<S>,
        remote_addr: (String, u16),
        resolver: ThreadSafeDNSResolver,
    ) -> Self {
        Self {
            inner,
            flushed: true,
            pkt: None,
            remote_addr: remote_addr.try_into().expect("must into socks addr"),
            buf: vec![0u8; 65535],
            resolver,
        }
    }
}

impl<S> Sink<UdpPacket> for OutboundDatagramShadowsocks<S>
where
    S: DatagramSend + Unpin,
{
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

impl<S> Stream for OutboundDatagramShadowsocks<S>
where
    S: DatagramReceive + Unpin,
{
    type Item = UdpPacket;

    #[instrument(skip(self, cx))]
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut buf,
            ref inner,
            ..
        } = self.get_mut();

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
    w: tokio::sync::Mutex<SplitSink<AnyOutboundDatagram, UdpPacket>>,
    r: tokio::sync::Mutex<(SplitStream<AnyOutboundDatagram>, BytesMut)>,
}

impl ShadowsocksUdpIo {
    pub fn new(inner: AnyOutboundDatagram) -> Self {
        let (w, r) = inner.split();
        Self {
            w: tokio::sync::Mutex::new(w),
            r: tokio::sync::Mutex::new((r, BytesMut::new())),
        }
    }
}

impl DatagramSend for ShadowsocksUdpIo {
    fn poll_send(&self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(new_io_error("not supported for shadowsocks udp io")))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: std::net::SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let mut w = self.w.try_lock().expect("must acquire");
        match w.start_send_unpin(UdpPacket {
            data: buf.to_vec(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target.into(),
        }) {
            Ok(_) => {}
            Err(e) => return Poll::Ready(Err(new_io_error(e.to_string()))),
        }
        match w.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(new_io_error(e.to_string())))
            }
            Poll::Pending => return Poll::Pending,
        }
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut w = self.w.try_lock().expect("must acquire");
        w.poll_ready_unpin(cx)
            .map_err(|e| new_io_error(e.to_string()))
    }
}

impl DatagramReceive for ShadowsocksUdpIo {
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = self.r.try_lock().expect("must acquire");
        let (r, remained) = &mut *g;

        if !remained.is_empty() {
            let to_consume = buf.remaining().min(remained.len());
            let consume = remained.split_to(to_consume);
            buf.put_slice(&consume);
            Poll::Ready(Ok(()))
        } else {
            match r.poll_next_unpin(cx) {
                Poll::Ready(Some(pkt)) => {
                    let to_comsume = buf.remaining().min(pkt.data.len());
                    let consume = pkt.data[..to_comsume].to_vec();
                    buf.put_slice(&consume);
                    if to_comsume < pkt.data.len() {
                        remained.extend_from_slice(&pkt.data[to_comsume..]);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
            }
        }
    }

    fn poll_recv_from(
        &self,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<std::net::SocketAddr>> {
        Poll::Ready(Err(new_io_error("not supported for shadowsocks udp io")))
    }

    fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
