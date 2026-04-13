/// XTLS-splice capable TLS stream.
///
/// Wraps a `TlsStream<AnyStream>` and can switch to raw (bypass-TLS) mode when
/// signalled via shared `Arc<AtomicBool>` flags.  This is required for
/// XTLS-Vision: after both sides exchange `CMD_PADDING_DIRECT`, they bypass the
/// outer Reality-TLS layer and communicate over the raw TCP socket.
use std::{
    io::{self, Read},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::proxy::AnyStream;

pub type RealityTlsStream = tokio_watfaq_rustls::client::TlsStream<AnyStream>;

/// Options passed to `VisionStream` when XTLS-splice mode is active.
///
/// Shared `Arc<AtomicBool>` flags are written by `VisionStream` when it
/// detects `CMD_PADDING_DIRECT`, and read by `SplicableTlsStream` to know
/// when to bypass the Reality TLS layer.
pub struct VisionOptions {
    pub read_flag: Arc<AtomicBool>,
    pub write_flag: Arc<AtomicBool>,
}

pub struct SplicableTlsStream {
    tls: RealityTlsStream,

    // Bytes drained from TLS plaintext buffer on the first raw-read.
    leftover: BytesMut,

    // Shared with VisionStream: set when CMD_DIRECT is received from server.
    read_flag: Arc<AtomicBool>,
    read_spliced: bool,

    // Shared with VisionStream: set when CMD_DIRECT is sent to server.
    write_flag: Arc<AtomicBool>,
    write_spliced: bool,
}

impl SplicableTlsStream {
    pub fn new(
        tls: RealityTlsStream,
        read_flag: Arc<AtomicBool>,
        write_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            tls,
            leftover: BytesMut::new(),
            read_flag,
            read_spliced: false,
            write_flag,
            write_spliced: false,
        }
    }

    /// Drain the TLS plaintext buffer into `self.leftover` and flip
    /// `read_spliced`.  After this, reads go directly to the raw IO.
    fn activate_read_splice(&mut self) {
        debug!("SplicableTlsStream: activating read splice (bypassing Reality TLS)");
        let (_, conn) = self.tls.get_mut();
        let mut tmp = [0u8; 4096];
        loop {
            match conn.reader().read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => self.leftover.put_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        self.read_spliced = true;
    }

    fn activate_write_splice(&mut self) {
        debug!(
            "SplicableTlsStream: activating write splice (bypassing Reality TLS)"
        );
        self.write_spliced = true;
    }
}

impl AsyncRead for SplicableTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Check if we need to switch to raw read.
        if !this.read_spliced && this.read_flag.load(Ordering::Acquire) {
            this.activate_read_splice();
        }

        // Return leftover plaintext drained from TLS first.
        if !this.leftover.is_empty() {
            let amt = this.leftover.len().min(buf.remaining());
            buf.put_slice(&this.leftover[..amt]);
            this.leftover.advance(amt);
            return Poll::Ready(Ok(()));
        }

        if this.read_spliced {
            // Bypass Reality TLS — read raw bytes from the underlying IO.
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_read(cx, buf)
        } else {
            Pin::new(&mut this.tls).poll_read(cx, buf)
        }
    }
}

impl AsyncWrite for SplicableTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.write_spliced && this.write_flag.load(Ordering::Acquire) {
            this.activate_write_splice();
        }

        if this.write_spliced {
            // Bypass Reality TLS — write raw bytes to the underlying IO.
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_write(cx, buf)
        } else {
            Pin::new(&mut this.tls).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_spliced {
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_flush(cx)
        } else {
            Pin::new(&mut this.tls).poll_flush(cx)
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_spliced {
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_shutdown(cx)
        } else {
            Pin::new(&mut this.tls).poll_shutdown(cx)
        }
    }
}
