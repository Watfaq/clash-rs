use async_trait::async_trait;
use base64::Engine;
use bytes::{BufMut, BytesMut};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::{AnyStream, transport::Transport};

pub struct Client {
    host: String,
    port: u16,
}

impl Client {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        Ok(HTTPObfs::new(stream, self.host.clone(), self.port).into())
    }
}

pub struct HTTPObfs {
    inner: AnyStream,
    host: String,
    port: u16,

    first_request: bool,
    first_response: bool,
    // write-side: in-flight HTTP-wrapped buffer and how many source bytes it
    // represents (> 0 while a first-request chunk is being drained)
    write_buf: Vec<u8>,
    write_pos: usize,
    write_committed: usize,
    // read-side: accumulates response bytes until \r\n\r\n is located
    read_buf: BytesMut,
}

/// Drain `this.write_buf[this.write_pos..]` into the inner stream, advancing
/// `this.write_pos` with each partial write.  Returns `Poll::Ready(Ok(()))`
/// once all bytes have been sent.
fn drain_write_buf(
    this: &mut HTTPObfs,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while this.write_pos < this.write_buf.len() {
        let n = ready!(
            Pin::new(&mut this.inner)
                .poll_write(cx, &this.write_buf[this.write_pos..])
        )?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
        }
        this.write_pos += n;
    }
    Poll::Ready(Ok(()))
}

impl AsyncWrite for HTTPObfs {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // If a previous first-request chunk is still being drained, finish it
        // before accepting new data.  The caller will supply the same `buf`
        // again (AsyncWrite contract), so returning `Ok(write_committed)` is
        // correct: it tells the caller those source bytes were consumed.
        if this.write_committed > 0 {
            ready!(drain_write_buf(this, cx))?;
            let committed = this.write_committed;
            this.write_committed = 0;
            return Poll::Ready(Ok(committed));
        }

        if this.first_request {
            // Build the HTTP upgrade request: headers + payload in one buffer.
            let rand_bytes = rand::random::<[u8; 16]>();
            let mut buffer = Vec::new();
            buffer.put_slice(b"GET / HTTP/1.1\r\n");
            buffer.put_slice(
                format!(
                    "Host: {}\r\n",
                    if this.port != 80 {
                        format!("{}:{}", this.host, this.port)
                    } else {
                        this.host.clone()
                    }
                )
                .as_bytes(),
            );
            buffer.put_slice(
                format!(
                    "User-Agent: curl/7.{}.{}\r\n",
                    rand::random_range(0..54),
                    rand::random_range(0..2),
                )
                .as_bytes(),
            );
            buffer.put_slice(b"Upgrade: websocket\r\n");
            buffer.put_slice(b"Connection: Upgrade\r\n");
            buffer.put_slice(
                format!(
                    "Sec-WebSocket-Key: {}\r\n",
                    base64::engine::general_purpose::STANDARD.encode(rand_bytes)
                )
                .as_bytes(),
            );
            buffer
                .put_slice(format!("Content-Length: {}\r\n", buf.len()).as_bytes());
            buffer.put_slice(b"\r\n");
            buffer.put_slice(buf);

            let n = buf.len(); // source bytes consumed (payload only)
            this.first_request = false;
            this.write_buf = buffer;
            this.write_pos = 0;
            this.write_committed = n;

            // Attempt to drain synchronously; if Pending, write_buf/write_pos
            // and write_committed survive in the struct for the next poll.
            ready!(drain_write_buf(this, cx))?;
            this.write_committed = 0;
            Poll::Ready(Ok(n))
        } else {
            // Subsequent writes: forward directly, no buffering needed.
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        // Drain any in-flight first-request write before flushing.
        ready!(drain_write_buf(this, cx))?;
        this.write_committed = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        // Drain any in-flight first-request write before shutting down.
        ready!(drain_write_buf(this, cx))?;
        this.write_committed = 0;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for HTTPObfs {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Deliver any leftover body bytes from a previous read first.
        if !this.read_buf.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), this.read_buf.len());
            // to_read > 0 because read_buf is non-empty and buf.remaining() > 0
            // (the caller would not call poll_read with a full buffer).
            let data = this.read_buf.split_to(to_read);
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }

        if this.first_response {
            // Accumulate response bytes in `this.read_buf` until the HTTP
            // response header terminator (\r\n\r\n) is found.  A single read
            // may not contain the full header, so we loop until we either find
            // the delimiter, hit an error, or the inner stream returns Pending.
            let needle = b"\r\n\r\n";
            loop {
                let mut tmp = [0u8; 4096];
                let mut tmp_buf = ReadBuf::new(&mut tmp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let filled = tmp_buf.filled();
                        if filled.is_empty() {
                            // Peer closed the connection before sending headers.
                            return Poll::Ready(Err(io::Error::from(
                                io::ErrorKind::UnexpectedEof,
                            )));
                        }
                        this.read_buf.put_slice(filled);

                        let idx = this
                            .read_buf
                            .windows(needle.len())
                            .position(|w| w == needle);

                        if let Some(idx) = idx {
                            this.first_response = false;
                            // Discard everything up to and including \r\n\r\n.
                            let _ = this.read_buf.split_to(idx + needle.len());
                            // Deliver what remains of the body to the caller.
                            let to_read =
                                std::cmp::min(buf.remaining(), this.read_buf.len());
                            if to_read > 0 {
                                let data = this.read_buf.split_to(to_read);
                                buf.put_slice(&data);
                            }
                            return Poll::Ready(Ok(()));
                        }
                        // Delimiter not yet seen — read more.
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        } else {
            Pin::new(&mut this.inner).poll_read(cx, buf)
        }
    }
}

impl HTTPObfs {
    pub fn new(inner: AnyStream, host: String, port: u16) -> Self {
        Self {
            inner,
            host,
            port,

            first_request: true,
            first_response: true,
            write_buf: Vec::new(),
            write_pos: 0,
            write_committed: 0,
            read_buf: BytesMut::new(),
        }
    }
}

impl From<HTTPObfs> for AnyStream {
    fn from(obfs: HTTPObfs) -> Self {
        Box::new(obfs)
    }
}
