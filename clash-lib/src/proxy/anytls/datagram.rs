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
    target_addr: SocksAddr,

    // Write state
    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,
    flushed: bool,

    // Read state
    read_buf: Vec<u8>,
    header_read: usize,
    packet_len: Option<usize>,
    packet_buf: BytesMut,
    length_buf: [u8; 2],
}

impl OutboundDatagramAnytls {
    pub fn new(inner: AnyStream, target_addr: SocksAddr) -> Self {
        Self {
            inner,
            target_addr,
            write_buf: BytesMut::new(),
            pending_packet: None,
            flushed: true,
            read_buf: vec![0u8; u16::MAX as usize],
            header_read: 0,
            packet_len: None,
            packet_buf: BytesMut::new(),
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
            if this.packet_len.is_none() {
                let mut length_read_buf =
                    ReadBuf::new(&mut this.length_buf[this.header_read..]);
                match ready!(inner.as_mut().poll_read(cx, &mut length_read_buf)) {
                    Ok(()) => {
                        let read = length_read_buf.filled().len();
                        if read == 0 {
                            return Poll::Ready(None);
                        }

                        this.header_read += read;
                        if this.header_read < this.length_buf.len() {
                            continue; // keep looping; poll_read will register waker when it returns Pending
                        }

                        let packet_len =
                            u16::from_be_bytes(this.length_buf) as usize;
                        this.header_read = 0;
                        if packet_len == 0 {
                            continue;
                        }
                        if packet_len > MAX_PACKET_LENGTH {
                            debug!(
                                "invalid anytls udp packet length: {}",
                                packet_len
                            );
                            return Poll::Ready(None);
                        }

                        this.packet_len = Some(packet_len);
                        this.packet_buf.clear();
                        this.packet_buf.reserve(packet_len);
                    }
                    Err(err) => {
                        debug!("failed to read anytls udp length header: {}", err);
                        return Poll::Ready(None);
                    }
                }
            }

            if let Some(packet_len) = this.packet_len {
                let remaining = packet_len.saturating_sub(this.packet_buf.len());
                let to_read = std::cmp::min(remaining, this.read_buf.len());
                let mut read_buf = ReadBuf::new(&mut this.read_buf[..to_read]);
                match ready!(inner.as_mut().poll_read(cx, &mut read_buf)) {
                    Ok(()) => {
                        let data = read_buf.filled();
                        if data.is_empty() {
                            return Poll::Ready(None);
                        }
                        this.packet_buf.put_slice(data);

                        if this.packet_buf.len() == packet_len {
                            let data = this.packet_buf.split_to(packet_len).to_vec();
                            this.packet_len = None;
                            return Poll::Ready(Some(UdpPacket {
                                data,
                                src_addr: this.target_addr.clone(),
                                dst_addr: this.target_addr.clone(),
                                inbound_user: None,
                            }));
                        }
                    }
                    Err(err) => {
                        debug!("failed to read anytls udp payload: {}", err);
                        return Poll::Ready(None);
                    }
                }
            }
        }
    }
}
