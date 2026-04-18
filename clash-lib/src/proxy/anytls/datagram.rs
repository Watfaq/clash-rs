use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

const MAX_PACKET_LENGTH: usize = u16::MAX as usize;

pub struct OutboundDatagramAnytls {
    inner: AnyStream,
    remote_addr: SocksAddr,

    // Write state
    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,
    flushed: bool,

    // Read state
    read_buf: Vec<u8>,
    remaining_bytes: usize,
    length_buf: [u8; 2],
}

impl OutboundDatagramAnytls {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,
            write_buf: BytesMut::new(),
            pending_packet: None,
            flushed: true,
            read_buf: vec![0u8; u16::MAX as usize],
            remaining_bytes: 0,
            length_buf: [0; 2],
        }
    }

    fn write_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "udp payload too large for anytls uot: {} > {}",
                    payload.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }

        self.write_buf.clear();
        self.write_buf.put_u16(payload.len() as u16);
        self.write_buf.put_slice(payload);
        Ok(())
    }
}

impl Sink<UdpPacket> for OutboundDatagramAnytls {
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
        let this = self.get_mut();
        if this.pending_packet.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous packet not yet sent",
            ));
        }
        this.write_packet(&item.data)?;
        this.pending_packet = Some(item);
        this.flushed = false;
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);
        while !this.write_buf.is_empty() {
            let n = ready!(inner.as_mut().poll_write(cx, &this.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write udp packet",
                )));
            }
            this.write_buf.advance(n);
        }

        ready!(inner.poll_flush(cx))?;

        if let Some(packet) = &this.pending_packet {
            trace!("sent anytls udp packet, len={}", packet.data.len());
        }

        this.pending_packet = None;
        this.flushed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for OutboundDatagramAnytls {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);

        loop {
            if this.remaining_bytes > 0 {
                let to_read =
                    std::cmp::min(this.remaining_bytes, this.read_buf.len());
                let mut read_buf = ReadBuf::new(&mut this.read_buf[..to_read]);
                match ready!(inner.as_mut().poll_read(cx, &mut read_buf)) {
                    Ok(()) => {
                        let data = read_buf.filled();
                        if data.is_empty() {
                            return Poll::Ready(None);
                        }
                        this.remaining_bytes -= data.len();
                        return Poll::Ready(Some(UdpPacket {
                            data: data.to_vec(),
                            src_addr: this.remote_addr.clone(),
                            dst_addr: this.remote_addr.clone(),
                            inbound_user: None,
                        }));
                    }
                    Err(err) => {
                        debug!("failed to read anytls udp payload: {}", err);
                        return Poll::Ready(None);
                    }
                }
            }

            let mut length_read_buf = ReadBuf::new(&mut this.length_buf);
            match ready!(inner.as_mut().poll_read(cx, &mut length_read_buf)) {
                Ok(()) => {
                    let data = length_read_buf.filled();
                    if data.is_empty() {
                        return Poll::Ready(None);
                    }
                    if data.len() < 2 {
                        debug!(
                            "incomplete anytls udp length header: {} bytes",
                            data.len()
                        );
                        return Poll::Ready(None);
                    }

                    let packet_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                    if packet_len == 0 {
                        continue;
                    }
                    if packet_len > MAX_PACKET_LENGTH {
                        debug!("invalid anytls udp packet length: {}", packet_len);
                        return Poll::Ready(None);
                    }
                    this.remaining_bytes = packet_len;
                }
                Err(err) => {
                    debug!("failed to read anytls udp length header: {}", err);
                    return Poll::Ready(None);
                }
            }
        }
    }
}
