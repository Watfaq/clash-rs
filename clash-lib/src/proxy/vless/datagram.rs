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

const MAX_PACKET_LENGTH: usize = 1024 << 3; // 8KB max packet length

pub struct OutboundDatagramVless {
    inner: AnyStream,
    remote_addr: SocksAddr,

    // Write state
    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,

    // Read state
    read_buf: Vec<u8>,
    remaining_bytes: usize,
    length_buf: [u8; 2],

    // State tracking
    flushed: bool,
}

impl OutboundDatagramVless {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,
            write_buf: BytesMut::new(),
            pending_packet: None,
            read_buf: vec![0u8; 65536],
            remaining_bytes: 0,
            length_buf: [0; 2],
            flushed: true,
        }
    }

    fn write_packet(&mut self, payload: &[u8]) -> Result<(), io::Error> {
        self.write_buf.clear();

        // VLESS UDP packet format is simpler than expected:
        // Just 2-byte length + payload data
        // No address encoding in the packet data phase!

        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "packet too large: {} > {}",
                    payload.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }

        // Write length header (big-endian)
        self.write_buf.put_u16(payload.len() as u16);

        // Write payload
        self.write_buf.put_slice(payload);

        trace!("encoded VLESS UDP packet: len={}", payload.len());
        Ok(())
    }
}

impl Sink<UdpPacket> for OutboundDatagramVless {
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

        // Handle large packets by chunking them
        let total_len = item.data.len();
        if total_len == 0 {
            return Ok(()); // Skip empty packets
        }

        // For now, handle first chunk or small packets
        let chunk_size = if total_len <= MAX_PACKET_LENGTH {
            total_len
        } else {
            MAX_PACKET_LENGTH
        };

        this.write_packet(&item.data[..chunk_size])?;
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

        if this.write_buf.is_empty() {
            this.flushed = true;
            this.pending_packet = None;
            return Poll::Ready(Ok(()));
        }

        let mut inner = Pin::new(&mut this.inner);

        // Write the encoded packet
        while !this.write_buf.is_empty() {
            let n = ready!(inner.as_mut().poll_write(cx, &this.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write packet data",
                )));
            }
            this.write_buf.advance(n);
        }

        // Flush the underlying stream
        ready!(inner.poll_flush(cx))?;

        if let Some(packet) = &this.pending_packet {
            debug!("sent VLESS UDP packet, data_len={}", packet.data.len());
        }

        this.flushed = true;
        this.pending_packet = None;

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

impl Stream for OutboundDatagramVless {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);

        loop {
            // If we have remaining bytes from a previous packet, read them
            if this.remaining_bytes > 0 {
                let to_read =
                    std::cmp::min(this.remaining_bytes, this.read_buf.len());
                let mut read_buf = ReadBuf::new(&mut this.read_buf[..to_read]);

                match ready!(inner.as_mut().poll_read(cx, &mut read_buf)) {
                    Ok(()) => {
                        let data = read_buf.filled();
                        if data.is_empty() {
                            return Poll::Ready(None); // Connection closed
                        }

                        this.remaining_bytes -= data.len();

                        trace!(
                            "received VLESS UDP packet chunk, len={}, remaining={}",
                            data.len(),
                            this.remaining_bytes
                        );

                        return Poll::Ready(Some(UdpPacket {
                            data: data.to_vec(),
                            src_addr: this.remote_addr.clone(),
                            dst_addr: this.remote_addr.clone(),
                        }));
                    }
                    Err(e) => {
                        debug!("failed to read packet data: {}", e);
                        return Poll::Ready(None);
                    }
                }
            }

            // Read the 2-byte length header
            let mut length_read_buf = ReadBuf::new(&mut this.length_buf);
            match ready!(inner.as_mut().poll_read(cx, &mut length_read_buf)) {
                Ok(()) => {
                    let data = length_read_buf.filled();
                    if data.len() < 2 {
                        if data.is_empty() {
                            return Poll::Ready(None); // Connection closed
                        }
                        debug!("incomplete length header: {} bytes", data.len());
                        return Poll::Ready(None);
                    }

                    let packet_len = u16::from_be_bytes([data[0], data[1]]) as usize;

                    if packet_len == 0 {
                        trace!("received empty packet");
                        continue; // Skip empty packets
                    }

                    if packet_len > MAX_PACKET_LENGTH {
                        debug!("packet too large: {} bytes", packet_len);
                        return Poll::Ready(None);
                    }

                    // Set up to read the packet data
                    this.remaining_bytes = packet_len;

                    trace!("expecting VLESS UDP packet of {} bytes", packet_len);
                }
                Err(e) => {
                    debug!("failed to read length header: {}", e);
                    return Poll::Ready(None);
                }
            }
        }
    }
}
