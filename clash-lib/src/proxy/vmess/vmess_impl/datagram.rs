use std::{io, pin::Pin, task::Poll};

use futures::{Sink, Stream, ready};
use tracing::{debug, error, instrument};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
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

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
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
                error!(
                    "udp packet dst_addr not match, pkt.dst_addr: {}, remote_addr: \
                     {}",
                    pkt.dst_addr, remote_addr
                );
                return Poll::Ready(Err(io::Error::other(
                    "udp packet dst_addr not match",
                )));
            }

            // Loop until the entire payload is written.  TCP streams may
            // accept fewer bytes than requested (partial write), and the
            // previous single-shot poll_write returned an error in that case,
            // causing intermittent UDP packet loss.  Also guard against
            // poll_write returning Ok(0) (closed stream) to avoid an infinite
            // loop.
            if written.is_none() {
                *written = Some(0);
            }
            let written_val = written.as_mut().unwrap();
            while *written_val < pkt.data.len() {
                let n = ready!(
                    inner.as_mut().poll_write(cx, &pkt.data[*written_val..])
                )?;
                if n == 0 {
                    *pkt_container = None;
                    *written = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write entire vmess udp packet: stream closed",
                    )));
                }
                *written_val += n;
                debug!(
                    "send udp packet to remote vmess server, len: {}, written: {}, \
                     total: {}, remote_addr: {}, dst_addr: {}",
                    n,
                    *written_val,
                    pkt.data.len(),
                    remote_addr,
                    pkt.dst_addr
                );
            }

            if !*flushed {
                let r = inner.as_mut().poll_flush(cx)?;
                if r.is_pending() {
                    return Poll::Pending;
                }
                *flushed = true;
            }

            *pkt_container = None;
            *written = None;
            Poll::Ready(Ok(()))
        } else {
            debug!("no udp packet to send");
            Poll::Ready(Err(io::Error::other("no packet to send")))
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
                inbound_user: None,
            })),
            Err(_) => Poll::Ready(None),
        }
    }
}
