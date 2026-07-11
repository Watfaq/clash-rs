//! A `quinn` bidirectional stream (`SendStream` + `RecvStream`) exposed as a
//! single `AsyncRead + AsyncWrite` object for the dispatcher. Shared by the
//! Hysteria2 outbound (client) and inbound (server) sides.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct HystStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// Bytes read past the framed header that must be delivered before reading
    /// further from the QUIC stream. Empty for the client side.
    prefix: Bytes,
}

impl HystStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send,
            recv,
            prefix: Bytes::new(),
        }
    }

    /// Like [`new`](Self::new) but delivers `prefix` before the stream — used
    /// by the server to preserve payload bytes pipelined into the request
    /// frame.
    pub fn with_prefix(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        prefix: Bytes,
    ) -> Self {
        Self { send, recv, prefix }
    }
}

impl std::fmt::Debug for HystStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystStream").finish()
    }
}

impl AsyncRead for HystStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..n]);
            let _ = this.prefix.split_to(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for HystStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map_err(|e| {
                tracing::error!("hysteria2 write error: {}", e);
                e.into()
            })
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}
