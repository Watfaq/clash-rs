use std::{fmt::Debug, pin::Pin, task::Poll};

use bytes::{Bytes, BytesMut};
use futures::{ready, Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

use crate::{
    common::errors::{map_io_error, new_io_error},
    proxy::AnyStream,
};

pub struct WebsocketConn {
    inner: WebSocketStream<AnyStream>,
    read_buffer: BytesMut,
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
            read_buffer: BytesMut::new(),
        }
    }
}

impl AsyncRead for WebsocketConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
            let for_read = self.read_buffer.split_to(to_read);
            buf.put_slice(&for_read[..to_read]);
            return std::task::Poll::Ready(Ok(()));
        }
        Poll::Ready(ready!(Pin::new(&mut self.inner).poll_next(cx)).map_or(
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "ws broken pipe",
            )),
            |item| {
                item.map_or(
                    Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "ws broken pipe",
                    )),
                    |msg| match msg {
                        Message::Binary(data) => {
                            let to_read = std::cmp::min(buf.remaining(), data.len());
                            buf.put_slice(&data[..to_read]);
                            if to_read < data.len() {
                                self.read_buffer.extend_from_slice(&data[to_read..]);
                            }
                            Ok(())
                        }
                        Message::Close(_) => Ok(()),
                        _ => Err(new_io_error("ws invalid message type")),
                    },
                )
            },
        ))
    }
}

impl AsyncWrite for WebsocketConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(map_io_error)?;
        let message = Message::Binary(Bytes::copy_from_slice(buf));
        Pin::new(&mut self.inner)
            .start_send(message)
            .map_err(map_io_error)?;
        ready!(self.poll_flush(cx)?);
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
