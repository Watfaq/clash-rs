use crate::{common::errors::new_io_error, session::TargetAddr};
use futures::{Sink, Stream, ready};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{io::ReadBuf, net::UdpSocket};
use watfaq_resolver::{AbstractResolver, Resolver};

pub use watfaq_types::UdpPacket;

#[must_use = "sinks do nothing unless polled"]
// TODO: maybe we should use abstract datagram IO interface instead of the
// Stream + Sink trait
pub struct OutboundDatagramImpl {
    inner: UdpSocket,
    resolver: Arc<Resolver>,
    flushed: bool,
    pkt: Option<UdpPacket>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: Arc<Resolver>) -> Self {
        Self {
            inner: udp,
            resolver,
            flushed: true,
            pkt: None,
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramImpl {
    type Error = watfaq_error::Error;

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
                TargetAddr::Domain(domain, port) => unimplemented!(),
                TargetAddr::Socket(addr) => *addr,
            };

            let n = ready!(inner.poll_send_to(cx, data.as_slice(), dst))?;
            let wrote_all = n == data.len();
            self.pkt = None;
            self.flushed = true;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(anyhow!("failed to send all data, only sent {n} bytes"))
            };
            Poll::Ready(res)
        } else {
            Poll::Ready(Err(anyhow!("no packet to send")))
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
                    dst_addr: TargetAddr::any_ipv4(),
                }))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}
