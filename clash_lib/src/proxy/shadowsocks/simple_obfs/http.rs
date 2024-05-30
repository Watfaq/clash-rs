use std::pin::Pin;

use crate::proxy::AnyStream;
use base64::Engine;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug)]
pub struct HTTPObfs {
    inner: AnyStream,
    host: String,
    port: u16,

    first_request: bool,
    first_response: bool,
    read_buf: BytesMut,
}

impl AsyncWrite for HTTPObfs {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let pin = self.get_mut();
        if pin.first_request {
            let rand_bytes = rand::random::<[u8; 16]>();
            let mut buffer = Vec::new();
            buffer.put_slice(b"GET / HTTP/1.1\r\n");
            buffer.put_slice(
                format!(
                    "Host: {}\r\n",
                    if pin.port != 80 {
                        format!("{}:{}", pin.host, pin.port)
                    } else {
                        pin.host.clone()
                    }
                )
                .as_bytes(),
            );
            buffer.put_slice(
                format!(
                    "User-Agent: curl/7.{}.{}\r\n",
                    rand::random::<usize>() % 54,
                    rand::random::<usize>() % 2
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
            buffer.put_slice(format!("Content-Length: {}\r\n", buf.len()).as_bytes());
            buffer.put_slice(b"\r\n");
            buffer.put_slice(buf);

            pin.first_request = false;
            Pin::new(&mut pin.inner).poll_write(cx, &buffer)
        } else {
            Pin::new(&mut pin.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let pin = self.get_mut();
        Pin::new(&mut pin.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let pin = self.get_mut();
        Pin::new(&mut pin.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for HTTPObfs {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        // as long as the buffer is not empty, we should return the data in the buffer first
        if !pin.read_buf.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), pin.read_buf.len());
            if to_read == 0 {
                assert!(buf.remaining() > 0);
                return std::task::Poll::Pending;
            }

            let data = pin.read_buf.split_to(to_read);
            buf.put_slice(&data[..]);
            return std::task::Poll::Ready(Ok(()));
        }

        if pin.first_response {
            // TODO: move this static buffer size to global constant
            // maximum packet size of vmess/shadowsocks is about 16 KiB so define a buffer of 20 KiB to reduce the memory of each TCP relay
            let mut b = [0; 20 * 1024];
            let mut b = tokio::io::ReadBuf::new(&mut b);
            match Pin::new(&mut pin.inner).poll_read(cx, &mut b) {
                std::task::Poll::Ready(rv) => match rv {
                    Ok(_) => {
                        let needle = b"\r\n\r\n";
                        let idx = b
                            .filled()
                            .windows(needle.len())
                            .position(|window| window == needle);

                        if let Some(idx) = idx {
                            pin.first_response = false;
                            let body = &b.filled()[idx + 4..b.filled().len()];
                            if body.len() < buf.remaining() {
                                buf.put_slice(body);
                                std::task::Poll::Ready(Ok(()))
                            } else {
                                let to_read = &body[..buf.remaining()];
                                let to_buf = &body[buf.remaining()..];
                                buf.put_slice(to_read);
                                // use put_slice instead of clone_from_slice
                                pin.read_buf.put_slice(to_buf);
                                std::task::Poll::Ready(Ok(()))
                            }
                        } else {
                            std::task::Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "EOF",
                            )))
                        }
                    }
                    Err(e) => std::task::Poll::Ready(Err(e)),
                },
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        } else {
            Pin::new(&mut pin.inner).poll_read(cx, buf)
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
            read_buf: BytesMut::new(),
        }
    }
}

impl From<HTTPObfs> for AnyStream {
    fn from(obfs: HTTPObfs) -> Self {
        Box::new(obfs)
    }
}
