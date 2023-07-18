use std::pin::Pin;

use bytes::{BufMut, BytesMut};
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite};

use super::CHUNK_SIZE;
use super::MAX_CHUNK_SIZE;

pub(crate) struct ChunkReader {
    size_holder: [u8; 2],
    buf: BytesMut,
    pos: usize,
}

impl ChunkReader {
    pub fn new() -> Self {
        Self {
            size_holder: [0; 2],
            buf: BytesMut::new(),
            pos: 0,
        }
    }

    pub fn poll_read<R>(
        self: std::pin::Pin<&mut Self>,
        inner: &mut R,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let Self {
            size_holder,
            buf: inner_buf,
            pos,
        } = self.get_mut();

        if !inner_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), inner_buf.len() - *pos);
            buf.put_slice(&inner_buf[*pos..*pos + n]);
            *pos += n;

            if *pos == inner_buf.len() {
                inner_buf.clear();
                *pos = 0;
            }

            return std::task::Poll::Ready(Ok(()));
        } else {
            assert!(*pos == 0, "chunk reader bad state");

            let mut pin = Pin::new(inner);
            let mut size_buf = tokio::io::ReadBuf::new(size_holder);
            ready!(pin.as_mut().poll_read(cx, &mut size_buf))?;
            if size_buf.filled().len() != 2 {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                )));
            }

            let size = u16::from_be_bytes(size_buf.filled().try_into().unwrap()) as usize;
            if size > MAX_CHUNK_SIZE {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "chunk size too large",
                )));
            }

            inner_buf.reserve(size);

            let mut chunk_buf = tokio::io::ReadBuf::new(inner_buf);
            ready!(pin.as_mut().poll_read(cx, &mut chunk_buf))?;
            if chunk_buf.filled().len() != size {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                )));
            }

            let n = buf.remaining();
            buf.put_slice(&inner_buf[..n]);
            *pos += n;

            if *pos == inner_buf.len() {
                inner_buf.clear();
                *pos = 0;
            }

            return std::task::Poll::Ready(Ok(()));
        }
    }
}

pub(crate) struct ChunkWriter {
    buf: BytesMut,
}

impl ChunkWriter {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    pub fn poll_write<W>(
        self: Pin<&mut Self>,
        inner: &mut W,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>>
    where
        W: AsyncWrite + Unpin,
    {
        let mut remaining = buf.len();
        let mut sent = 0;

        let Self { buf: inner_buf } = self.get_mut();

        let mut pin = Pin::new(inner);

        while remaining > 0 {
            let payload_size = std::cmp::min(remaining, CHUNK_SIZE);

            inner_buf.reserve(2 + payload_size);
            inner_buf.put_u16(payload_size as u16);
            inner_buf.put_slice(&buf[sent..sent + payload_size]);

            ready!(pin.as_mut().poll_write(cx, inner_buf))?;
            inner_buf.clear();

            sent += payload_size;
            remaining -= payload_size;
        }

        std::task::Poll::Ready(Ok(buf.len()))
    }
}
