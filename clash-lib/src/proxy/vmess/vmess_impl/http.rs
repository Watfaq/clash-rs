use std::{
    collections::HashMap,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, BufStream, ReadBuf};

use crate::{
    common::{errors::map_io_error, utils},
    proxy::AnyStream,
};

pub struct HttpConfig {
    pub method: String,
    pub host: String,
    pub path: Vec<String>,
    pub headers: HashMap<String, String>,
}

impl HttpConfig {
    pub fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let idx = utils::rand_range(0..self.path.len());
        let path = self.path[idx].clone();
        Ok(Box::new(HttpStream::new(
            stream,
            self.host.clone(),
            path,
            self.headers.clone(),
        )))
    }
}

/// HTTP obfuscation stream for VMess.
///
/// **Write side**: the first `poll_write` prepends HTTP request headers to the
/// caller's data.  Subsequent writes pass through as-is.  The in-flight buffer
/// is stored in `write_buf`/`write_pos`/`write_committed` so a `Poll::Pending`
/// from the inner stream never causes the encoded bytes to be lost.
///
/// **Read side**: `buf` accumulates raw bytes from the inner stream until a
/// complete HTTP response header has been parsed and skipped.  Any body bytes
/// that arrived in the same read as the last header chunk are held in `buf`
/// and delivered on the next `poll_read` call.  Because `buf` lives in the
/// struct, a `Poll::Pending` return never discards already-received bytes.
pub struct HttpStream {
    bufio: BufStream<AnyStream>,
    host: String,
    path: String,
    headers: HashMap<String, String>,
    /// Before `header_consumed`: accumulates incoming bytes while we search
    /// for the end of the HTTP response header.
    /// After `header_consumed`: holds any body bytes that arrived together
    /// with the last header chunk, to be delivered on the next read.
    buf: BytesMut,
    header_consumed: bool,
    /// True once the HTTP request headers have been sent at least once.
    header_sent: bool,
    /// Encoded wire bytes waiting to be drained into `bufio`.
    write_buf: BytesMut,
    /// How many bytes of `write_buf` have already been accepted by `bufio`.
    write_pos: usize,
    /// How many bytes of the *caller's* `buf` the current `write_buf` encodes.
    write_committed: usize,
}

impl HttpStream {
    pub fn new(
        stream: AnyStream,
        host: String,
        path: String,
        headers: HashMap<String, String>,
    ) -> Self {
        Self {
            bufio: BufStream::new(stream),
            host,
            path,
            headers,
            buf: BytesMut::new(),
            header_consumed: false,
            header_sent: false,
            write_buf: BytesMut::new(),
            write_pos: 0,
            write_committed: 0,
        }
    }
}

/// Drain `this.write_buf[this.write_pos..]` into the inner buffered stream,
/// advancing `this.write_pos` after each partial write.
fn drain_write_buf(this: &mut HttpStream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    while this.write_pos < this.write_buf.len() {
        let n = ready!(
            Pin::new(&mut this.bufio).poll_write(cx, &this.write_buf[this.write_pos..])
        )?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
        }
        this.write_pos += n;
    }
    Poll::Ready(Ok(()))
}

impl AsyncRead for HttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut pin = Pin::new(&mut this.bufio);

        if !this.header_consumed {
            // Accumulate bytes in `this.buf` until we can parse a complete
            // HTTP response header.  `this.buf` survives Poll::Pending so no
            // bytes already pulled from the inner stream are ever lost.
            loop {
                {
                    let mut headers = [httparse::EMPTY_HEADER; 16];
                    let mut resp = httparse::Response::new(&mut headers);
                    match resp.parse(&this.buf).map_err(map_io_error)? {
                        httparse::Status::Complete(offset) => {
                            // Split header bytes off; keep only the trailing
                            // body bytes (if any) for the next poll_read call.
                            let body = this.buf.split_off(offset);
                            this.buf = body;
                            this.header_consumed = true;
                            break;
                        }
                        httparse::Status::Partial => { /* need more bytes */ }
                    }
                }
                // Use a stack-allocated scratch buffer so the inner stream
                // has real capacity to write into.  Passing a ReadBuf built
                // from a zero-length BytesMut (as the original code did)
                // gives the inner stream 0 capacity and can never make
                // progress.
                let mut tmp = [0u8; 1024];
                let mut rb = ReadBuf::new(&mut tmp);
                ready!(pin.as_mut().poll_read(cx, &mut rb))?;
                let filled = rb.filled();
                if filled.is_empty() {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                }
                this.buf.extend_from_slice(filled);
            }
        }

        // Deliver any body bytes that arrived alongside the last header chunk.
        if !this.buf.is_empty() {
            let to_read = this.buf.len().min(buf.remaining());
            buf.put_slice(&this.buf[..to_read]);
            let _ = this.buf.split_to(to_read);
            return Poll::Ready(Ok(()));
        }

        // No buffered bytes — read directly from the inner stream.
        pin.poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // A previous write is still being drained (we returned Poll::Pending
        // last time).  Finish sending those bytes first, then report how many
        // of the caller's source bytes they represented.  The caller will
        // re-issue poll_write with the same buf once it gets Poll::Ready.
        if this.write_committed > 0 {
            ready!(drain_write_buf(this, cx))?;
            let committed = this.write_committed;
            this.write_committed = 0;
            this.write_pos = 0;
            this.write_buf.clear();
            return Poll::Ready(Ok(committed));
        }

        // Build the wire buffer: HTTP request headers (first write only)
        // followed by the caller's payload.
        this.write_buf.clear();
        if !this.header_sent {
            this.header_sent = true;
            let req_line = format!("GET {} HTTP/1.1\r\n", this.path);
            this.write_buf.put_slice(req_line.as_bytes());
            let host_line = format!("Host: {}\r\n", this.host);
            this.write_buf.put_slice(host_line.as_bytes());
            for (k, v) in this.headers.iter() {
                let header_line = format!("{}: {}\r\n", k, v);
                this.write_buf.put_slice(header_line.as_bytes());
            }
        }
        this.write_buf.put_slice(buf);
        this.write_pos = 0;
        this.write_committed = buf.len();

        ready!(drain_write_buf(this, cx))?;
        let committed = this.write_committed;
        this.write_committed = 0;
        Poll::Ready(Ok(committed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(drain_write_buf(this, cx))?;
        this.write_committed = 0;
        Pin::new(&mut this.bufio).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(drain_write_buf(this, cx))?;
        this.write_committed = 0;
        Pin::new(&mut this.bufio).poll_shutdown(cx)
    }
}
