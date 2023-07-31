use std::{fmt::Debug, pin::Pin};

use bytes::{Buf, Bytes};
use futures::{ready, Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

use crate::{
    common::errors::{map_io_error, new_io_error},
    proxy::AnyStream,
};

pub struct WebsocketConn {
    inner: WebSocketStream<AnyStream>,
    read_buffer: Option<Bytes>,
}

impl Debug for WebsocketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketConn")
            .field("inner", &self.inner)
            .field("read_buffer", &self.read_buffer)
            .finish()
    }
}

impl WebsocketConn {
    pub fn from_websocket(stream: WebSocketStream<AnyStream>) -> Self {
        Self {
            inner: stream,
            read_buffer: None,
        }
    }
}

impl AsyncRead for WebsocketConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if let Some(read_buffer) = &mut self.read_buffer {
                if read_buffer.len() <= buf.remaining() {
                    buf.put_slice(read_buffer);
                    self.read_buffer = None;
                } else {
                    buf.put_slice(&read_buffer[..buf.remaining()]);
                    read_buffer.advance(buf.remaining());
                }
                return std::task::Poll::Ready(Ok(()));
            }

            let message = ready!(Pin::new(&mut self.inner).poll_next(cx));

            if message.is_none() {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                )));
            }

            let message = message.unwrap().map_err(map_io_error)?;

            match message {
                tokio_tungstenite::tungstenite::Message::Binary(binary) => {
                    if binary.len() < buf.remaining() {
                        buf.put_slice(&binary);
                    } else {
                        buf.put_slice(&binary[..buf.remaining()]);
                        self.read_buffer = Some(Bytes::from(binary[buf.remaining()..].to_vec()));
                    }
                    return std::task::Poll::Ready(Ok(()));
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    return std::task::Poll::Ready(Ok(()))
                }
                _ => {
                    return std::task::Poll::Ready(Err(new_io_error("unexpected message type")));
                }
            }
        }
    }
}

impl AsyncWrite for WebsocketConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(map_io_error)?;
        let message = Message::Binary(buf.into());
        Pin::new(&mut self.inner)
            .start_send(message)
            .map_err(map_io_error)?;
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let Self { inner, .. } = self.get_mut();
        Pin::new(inner).poll_flush(cx).map_err(map_io_error)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let Self { inner, .. } = self.get_mut();
        let mut pin = Pin::new(inner);

        let message = Message::Close(None);
        #[allow(unused_must_use)]
        {
            pin.as_mut().start_send(message);
        }
        pin.poll_close(cx).map_err(map_io_error)
    }
}
