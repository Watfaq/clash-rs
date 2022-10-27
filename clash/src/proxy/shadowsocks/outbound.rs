use std::{
    io,
    pin::Pin,
    sync::RwLock,
    task::{Context, Poll},
};

use futures::{ready, FutureExt, Sink, Stream};
use shadowsocks::ProxySocket;

use crate::{
    proxy::{datagram::UdpPacket, AnyOutboundDatagram},
    session::SocksAddr,
};

#[must_use = "sinks do nothing unless polled"]
pub struct OutboundDatagramShadowsocks {
    inner: RwLock<ProxySocket>,
    remote_addr: (String, u16),
    flushed: bool,
    pkt: Option<UdpPacket>,
    buf: Vec<u8>,
}

impl OutboundDatagramShadowsocks {
    pub fn new(inner: ProxySocket, remote_addr: (String, u16)) -> AnyOutboundDatagram {
        let s = Self {
            inner: RwLock::new(inner),
            flushed: true,
            pkt: None,
            remote_addr,
            buf: Vec::with_capacity(65535),
        };
        Box::new(s) as _
    }
}

impl Sink<UdpPacket> for OutboundDatagramShadowsocks {
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
        let Self {
            ref mut inner,
            ref mut pkt,
            ref mut flushed,
            ref remote_addr,
            ..
        } = *self;

        let pkg_container = pkt;

        let guard = inner.write().expect("write lock");

        if *flushed {
            return Poll::Ready(Ok(()));
        }

        if let Some(pkt) = pkg_container.take() {
            let data = pkt.data;
            let addr: shadowsocks::relay::Address =
                (pkt.dst_addr.host(), pkt.dst_addr.port()).into();
            let mut fut = guard.send_to(remote_addr.to_owned(), &addr, &data).boxed();
            let n = ready!(fut.as_mut().poll(cx).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "send UDP data to remote ss server")
            }))?;

            let wrote_all = n == data.len();
            *pkg_container = None;
            *flushed = true;

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
impl Stream for OutboundDatagramShadowsocks {
    type Item = UdpPacket;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut buf,
            ref inner,
            ..
        } = *self;

        let guard = inner.read().expect("read lock");
        let mut fut = guard.recv_from(buf).boxed();
        let rv = ready!(fut.as_mut().poll(cx).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "recv UDP data from remote ss server")
        }));

        drop(fut); // drop the future to bypass the borrow checker

        match rv {
            Ok((n, src, _, _)) => Poll::Ready(Some(UdpPacket {
                data: (buf[..n]).to_vec(),
                src_addr: src.into(),
                dst_addr: SocksAddr::any_ipv4(),
            })),
            Err(_) => Poll::Ready(None),
        }
    }
}
