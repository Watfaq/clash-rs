use std::{io, pin::Pin, task::Poll};

use futures::{ready, Sink, Stream};
use tracing::{debug, instrument};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    proxy::{datagram::UdpPacket, AnyStream},
    session::SocksAddr,
};

pub struct OutboundDatagramVmess {
    inner: AnyStream,
    remote_addr: SocksAddr,

    written: Option<usize>,
    flushed: bool,
    pkt: Option<UdpPacket>,
    buf: Vec<u8>,
}

impl OutboundDatagramVmess {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,
            written: None,
            flushed: true,
            pkt: None,
            buf: vec![0u8; 65535],
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramVmess {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            ref mut pkt,
            ref remote_addr,
            ref mut flushed,
            ref mut written,
            ..
        } = *self;

        let mut inner = Pin::new(inner);

        let pkt_container = pkt;

        if let Some(pkt) = pkt_container {
            if &pkt.dst_addr != remote_addr {
                debug!(
                    "udp packet dst_addr not match, pkt.dst_addr: {}, remote_addr: {}",
                    pkt.dst_addr, remote_addr
                );
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "udp packet dst_addr not match",
                )));
            }

            if written.is_none() {
                let n = ready!(inner.as_mut().poll_write(cx, pkt.data.as_ref()))?;
                debug!(
                    "send udp packet to remote vmess server, len: {}, remote_addr: {}, dst_addr: {}",
                    n, remote_addr, pkt.dst_addr
                );
                *written = Some(n);
            }
            if !*flushed {
                let r = inner.as_mut().poll_flush(cx)?;
                if r.is_pending() {
                    return Poll::Pending;
                }
                *flushed = true;
            }
            let total_len = pkt.data.len();

            *pkt_container = None;

            let res = if written.unwrap() == total_len {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "failed to write entire datagram",
                ))
            };
            *written = None;
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
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl Stream for OutboundDatagramVmess {
    type Item = UdpPacket;

    #[instrument(skip(self, cx))]
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut buf,
            ref mut inner,
            ref remote_addr,
            ..
        } = *self;

        let inner = Pin::new(inner);

        let mut buf = ReadBuf::new(buf);

        let rv = ready!(inner.poll_read(cx, &mut buf));

        match rv {
            Ok(()) => Poll::Ready(Some(UdpPacket {
                data: buf.filled().to_vec(),
                src_addr: remote_addr.clone(),
                dst_addr: SocksAddr::any_ipv4(),
            })),
            Err(_) => Poll::Ready(None),
        }
    }
}
