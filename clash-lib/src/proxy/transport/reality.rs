use std::{
    io::{self, IoSlice, Read, Write},
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    sync::LazyLock,
    task::{Context, Poll},
};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;
use watfaq_rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, Error as RustlsError,
    RootCertStore, SideData,
    client::{ClientFingerprint, RealityConfig},
    pki_types::ServerName,
};

use super::Transport;
use crate::proxy::AnyStream;

static ROOT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let root_store: RootCertStore =
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    Arc::new(root_store)
});

pub struct RealityClient {
    sni: String,
    public_key: [u8; 32],
    short_id: Vec<u8>,
    alpn: Option<Vec<String>>,
    client_fingerprint: Option<String>,
}

impl RealityClient {
    pub fn new(
        sni: String,
        public_key: [u8; 32],
        short_id: Vec<u8>,
        alpn: Option<Vec<String>>,
        client_fingerprint: Option<String>,
    ) -> Self {
        Self {
            sni,
            public_key,
            short_id,
            alpn,
            client_fingerprint,
        }
    }
}

#[async_trait]
impl Transport for RealityClient {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let mut reality = RealityConfig::new(self.public_key, self.short_id.clone())
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?;

        if let Some(client_fingerprint) = self.client_fingerprint.as_deref() {
            let fingerprint = ClientFingerprint::from_name(client_fingerprint)
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
                })?;
            reality = reality.with_client_fingerprint(fingerprint);
        }

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(ROOT_STORE.clone())
            .with_reality(reality)
            .with_no_client_auth();

        if let Some(alpn) = &self.alpn {
            tls_config.alpn_protocols =
                alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }

        let sni: ServerName<'static> = ServerName::try_from(self.sni.clone())
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?;

        let conn = ClientConnection::new(Arc::new(tls_config), sni)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let tls = reality_tls_connect(stream, conn).await?;
        Ok(Box::new(tls) as AnyStream)
    }
}

// ─── Inline async TLS implementation ──────────────────────────────────────────
// Adapted from tokio-watfaq-rustls common module, using watfaq_rustls@0e01771a
// types directly.  This avoids the version mismatch between tokio-watfaq-rustls
// (built against @4cae3aa2) and our new @0e01771a ClientConfig.

struct RealityTlsStream<IO> {
    io: IO,
    session: ClientConnection,
    eof: bool,
    raw_write_mode: bool,
    raw_read_mode: bool,
    raw_read_buf: Vec<u8>,
    raw_read_pos: usize,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> RealityTlsStream<IO> {
    fn new(io: IO, session: ClientConnection) -> Self {
        Self {
            io,
            session,
            eof: false,
            raw_write_mode: false,
            raw_read_mode: false,
            raw_read_buf: Vec::new(),
            raw_read_pos: 0,
        }
    }

    fn switch_raw_write_mode(&mut self) {
        self.raw_write_mode = true;
    }

    fn switch_raw_read_mode(&mut self) {
        if self.raw_read_mode {
            return;
        }
        let (pending_plaintext, pending_raw) =
            self.session.take_vision_direct_buffers();
        let raw_head = pending_raw
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        let raw_full = if pending_raw.len() <= 64 {
            pending_raw
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("")
        } else {
            String::new()
        };
        debug!(
            "reality raw read switch: plaintext={} raw={} raw_head={} raw_full={}",
            pending_plaintext.len(),
            pending_raw.len(),
            raw_head,
            raw_full
        );
        self.raw_read_buf = pending_plaintext;
        self.raw_read_buf.extend_from_slice(&pending_raw);
        self.raw_read_pos = 0;
        self.raw_read_mode = true;
    }

    fn should_autoswitch_raw_read(err: &io::Error) -> bool {
        if err.kind() != io::ErrorKind::InvalidData {
            return false;
        }

        if let Some(inner) = err.get_ref() {
            if let Some(tls_err) = inner.downcast_ref::<RustlsError>() {
                return matches!(tls_err, RustlsError::DecryptError);
            }
        }

        err.to_string().contains("cannot decrypt peer's message")
    }

    fn read_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut reader = SyncReadAdapter {
            io: &mut self.io,
            cx,
        };
        let n = match self.session.read_tls(&mut reader) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Poll::Pending;
            }
            Err(e) => return Poll::Ready(Err(e)),
        };
        let io_state = self
            .session
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        debug!(
            "reality read_io: tls_read={} plaintext_ready={} tls_to_write={} wants_read={}",
            n,
            io_state.plaintext_bytes_to_read(),
            io_state.tls_bytes_to_write(),
            self.session.wants_read()
        );
        Poll::Ready(Ok(n))
    }

    fn write_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut writer = SyncWriteAdapter {
            io: &mut self.io,
            cx,
        };
        match self.session.write_tls(&mut writer) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    fn handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;
            let mut need_flush = false;

            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(_)) => need_flush = true,
                    Poll::Pending => {
                        write_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }

            if need_flush {
                match Pin::new(&mut self.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => write_would_block = true,
                }
            }

            while !self.eof && self.session.wants_read() {
                match self.read_io(cx) {
                    Poll::Ready(Ok(0)) => self.eof = true,
                    Poll::Ready(Ok(_)) => {}
                    Poll::Pending => {
                        read_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }

            if self.eof && self.session.is_handshaking() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tls handshake eof",
                )));
            }
            if !self.session.is_handshaking() {
                return Poll::Ready(Ok(()));
            }
            if write_would_block || read_would_block {
                return Poll::Pending;
            }
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityTlsStream<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.raw_read_mode {
            if self.raw_read_pos < self.raw_read_buf.len() {
                let remaining = &self.raw_read_buf[self.raw_read_pos..];
                let to_copy = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                self.raw_read_pos += to_copy;
                if self.raw_read_pos >= self.raw_read_buf.len() {
                    self.raw_read_buf.clear();
                    self.raw_read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut self.io).poll_read(cx, buf);
        }

        let mut io_pending = false;

        // Drain all currently-available TLS bytes each poll. For Vision traffic,
        // small trailing chunks (for example, record tails) may arrive just after
        // the first read and should be picked up without waiting for long timers.
        while !self.eof {
            match self.read_io(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(e)) => {
                    if !self.raw_read_mode
                        && self.raw_write_mode
                        && Self::should_autoswitch_raw_read(&e)
                    {
                        // Try draining already-decoded plaintext first.
                        // In Vision direct transition, decrypt errors can happen
                        // after we already decoded the final framed bytes.
                        match self.session.reader().read(buf.initialize_unfilled()) {
                            Ok(n) if n > 0 => {
                                buf.advance(n);
                                return Poll::Ready(Ok(()));
                            }
                            Ok(_) => {}
                            Err(ref read_err)
                                if read_err.kind() == io::ErrorKind::WouldBlock => {}
                            Err(read_err) => {
                                return Poll::Ready(Err(read_err));
                            }
                        }

                        self.switch_raw_read_mode();
                        if self.raw_read_pos < self.raw_read_buf.len() {
                            let remaining = &self.raw_read_buf[self.raw_read_pos..];
                            let to_copy = remaining.len().min(buf.remaining());
                            buf.put_slice(&remaining[..to_copy]);
                            self.raw_read_pos += to_copy;
                            if self.raw_read_pos >= self.raw_read_buf.len() {
                                self.raw_read_buf.clear();
                                self.raw_read_pos = 0;
                            }
                            return Poll::Ready(Ok(()));
                        }
                        return Pin::new(&mut self.io).poll_read(cx, buf);
                    }
                    return Poll::Ready(Err(e));
                }
            }
        }

        match self.session.reader().read(buf.initialize_unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if !io_pending {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityTlsStream<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.raw_write_mode {
            return Pin::new(&mut self.io).poll_write(cx, buf);
        }

        let mut pos = 0;
        while pos != buf.len() {
            let mut would_block = false;
            match self.session.writer().write(&buf[pos..]) {
                Ok(n) => pos += n,
                Err(e) => return Poll::Ready(Err(e)),
            }
            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
            return match (pos, would_block) {
                (0, true) => Poll::Pending,
                (n, true) => Poll::Ready(Ok(n)),
                (_, false) => continue,
            };
        }
        Poll::Ready(Ok(pos))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.raw_write_mode {
            return Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        }

        if bufs.iter().all(|b| b.is_empty()) {
            return Poll::Ready(Ok(0));
        }
        loop {
            let mut would_block = false;
            let written = self.session.writer().write_vectored(bufs)?;
            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
            return match (written, would_block) {
                (0, true) => Poll::Pending,
                (0, false) => continue,
                (n, _) => Poll::Ready(Ok(n)),
            };
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.raw_write_mode {
            return Pin::new(&mut self.io).poll_flush(cx);
        }

        self.session.writer().flush()?;
        while self.session.wants_write() {
            match self.write_io(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.raw_write_mode {
            return Pin::new(&mut self.io).poll_shutdown(cx);
        }

        while self.session.wants_write() {
            match self.write_io(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Adapter: `AsyncRead` → `std::io::Read`; returns `WouldBlock` on Pending.
struct SyncReadAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<'a, 'b, T: AsyncRead + Unpin> Read for SyncReadAdapter<'a, 'b, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Adapter: `AsyncWrite` → `std::io::Write`; returns `WouldBlock` on Pending.
struct SyncWriteAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<'a, 'b, T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'a, 'b, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write_vectored(self.cx, bufs) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Async connect: wraps IO + `ClientConnection` and performs TLS handshake.
struct RealityConnect<IO> {
    stream: Option<RealityTlsStream<IO>>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> std::future::Future for RealityConnect<IO> {
    type Output = io::Result<RealityTlsStream<IO>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let stream = this
            .stream
            .as_mut()
            .expect("RealityConnect polled after completion");

        match stream.handshake(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(this.stream.take().unwrap())),
            Poll::Ready(Err(e)) => {
                this.stream.take();
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn reality_tls_connect<IO: AsyncRead + AsyncWrite + Unpin>(
    io: IO,
    conn: ClientConnection,
) -> io::Result<RealityTlsStream<IO>> {
    RealityConnect {
        stream: Some(RealityTlsStream::new(io, conn)),
    }
    .await
}

pub(crate) fn switch_reality_raw_modes(
    stream: &mut AnyStream,
    read: bool,
    write: bool,
) -> io::Result<bool> {
    if let Some(reality_stream) =
        stream.downcast_mut::<RealityTlsStream<AnyStream>>()
    {
        if write {
            reality_stream.switch_raw_write_mode();
        }
        if read {
            reality_stream.switch_raw_read_mode();
        }
        return Ok(true);
    }

    Ok(false)
}

// Suppress unused type parameter warning for unused SideData bound
fn _assert_bounds<
    T: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
>() {
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_client_new() {
        let pk = [1u8; 32];
        let short_id = vec![0x1b, 0xc2, 0xc1, 0xef, 0x1c];
        let client = RealityClient::new(
            "www.microsoft.com".to_owned(),
            pk,
            short_id.clone(),
            None,
            None,
        );
        assert_eq!(client.sni, "www.microsoft.com");
        assert_eq!(client.public_key, pk);
        assert_eq!(client.short_id, short_id);
    }

    #[test]
    fn test_reality_config_construction() {
        let pk = [0u8; 32];
        let short_id = vec![0x12, 0x34];
        let result = RealityConfig::new(pk, short_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reality_config_short_id_too_long() {
        let pk = [0u8; 32];
        let short_id = vec![0u8; 9]; // 9 bytes > max 8
        let result = RealityConfig::new(pk, short_id);
        assert!(result.is_err());
    }
}
