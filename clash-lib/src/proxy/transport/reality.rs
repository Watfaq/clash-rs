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
use watfaq_rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, RootCertStore, SideData,
    client::RealityConfig,
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
}

impl RealityClient {
    pub fn new(
        sni: String,
        public_key: [u8; 32],
        short_id: Vec<u8>,
        alpn: Option<Vec<String>>,
    ) -> Self {
        Self {
            sni,
            public_key,
            short_id,
            alpn,
        }
    }
}

#[async_trait]
impl Transport for RealityClient {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let reality =
            RealityConfig::new(self.public_key, self.short_id.clone())
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
                })?;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(ROOT_STORE.clone())
            .with_reality(reality)
            .with_no_client_auth();

        if let Some(alpn) = &self.alpn {
            tls_config.alpn_protocols =
                alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }

        let sni: ServerName<'static> = ServerName::try_from(self.sni.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

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
}

impl<IO: AsyncRead + AsyncWrite + Unpin> RealityTlsStream<IO> {
    fn new(io: IO, session: ClientConnection) -> Self {
        Self {
            io,
            session,
            eof: false,
        }
    }

    fn read_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut reader = SyncReadAdapter { io: &mut self.io, cx };
        let n = match self.session.read_tls(&mut reader) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Poll::Pending
            }
            Err(e) => return Poll::Ready(Err(e)),
        };
        self.session
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Poll::Ready(Ok(n))
    }

    fn write_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut writer = SyncWriteAdapter { io: &mut self.io, cx };
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
        let mut io_pending = false;

        while !self.eof && self.session.wants_read() {
            match self.read_io(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
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
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
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
            Poll::Ready(Ok(())) => {
                Poll::Ready(Ok(this.stream.take().unwrap()))
            }
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

// Suppress unused type parameter warning for unused SideData bound
fn _assert_bounds<T: DerefMut + Deref<Target = ConnectionCommon<SD>>, SD: SideData>() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_client_new() {
        let pk = [1u8; 32];
        let short_id = vec![0x1b, 0xc2, 0xc1, 0xef, 0x1c];
        let client =
            RealityClient::new("www.microsoft.com".to_owned(), pk, short_id.clone(), None);
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
