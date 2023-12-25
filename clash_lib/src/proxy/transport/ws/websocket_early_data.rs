use std::{
    cmp,
    fmt::Debug,
    pin::Pin,
    task::{Poll, Waker},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures::ready;
use futures::Future;
use http::{HeaderValue, Request, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{client_async_with_config, tungstenite::protocol::WebSocketConfig};

use crate::{
    common::errors::{map_io_error, new_io_error},
    proxy::AnyStream,
};

use super::websocket::WebsocketConn;

pub struct WebsocketEarlyDataConn {
    stream: Option<AnyStream>,
    req: Option<Request<()>>,
    stream_future: Option<
        Pin<Box<dyn std::future::Future<Output = std::io::Result<AnyStream>> + Send + Sync>>,
    >,
    early_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    ws_config: Option<WebSocketConfig>,
    early_data_header_name: String,
    early_data_len: usize,
    early_data_flushed: bool,
}

impl Debug for WebsocketEarlyDataConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketEarlyDataConn")
            .field("stream", &self.stream)
            .field("req", &self.req)
            .field("early_waker", &self.early_waker)
            .field("flush_waker", &self.flush_waker)
            .field("ws_config", &self.ws_config)
            .field("early_data_header_name", &self.early_data_header_name)
            .field("early_data_len", &self.early_data_len)
            .field("early_data_flushed", &self.early_data_flushed)
            .finish()
    }
}

impl WebsocketEarlyDataConn {
    pub fn new(
        stream: AnyStream,
        req: Request<()>,
        ws_config: Option<WebSocketConfig>,
        early_data_header_name: String,
        early_data_len: usize,
    ) -> Self {
        Self {
            stream: Some(stream),
            req: Some(req),
            stream_future: None,
            early_waker: None,
            flush_waker: None,
            ws_config,
            early_data_header_name,
            early_data_len,
            early_data_flushed: false,
        }
    }

    fn proxy_stream(
        stream: AnyStream,
        req: Request<()>,
        config: Option<WebSocketConfig>,
    ) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<AnyStream>> + Send + Sync>> {
        async fn run(
            stream: AnyStream,
            req: Request<()>,
            config: Option<WebSocketConfig>,
        ) -> std::io::Result<AnyStream> {
            let (stream, resp) = client_async_with_config(req, stream, config)
                .await
                .map_err(map_io_error)?;
            if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(new_io_error("msg: websocket early data handshake failed"));
            }
            let rv = Box::new(WebsocketConn::from_websocket(stream));
            Ok(rv)
        }

        Box::pin(run(stream, req, config))
    }
}

impl AsyncRead for WebsocketEarlyDataConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.early_data_flushed {
            if self.early_waker.is_none() {
                self.as_mut().early_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let pin = self.get_mut();
        match &mut pin.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WebsocketEarlyDataConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if !self.early_data_flushed {
            loop {
                if let Some(fut) = &mut self.as_mut().stream_future {
                    let stream = ready!(Pin::new(fut).poll(cx))?;

                    self.as_mut().stream = Some(stream);
                    self.as_mut().early_data_flushed = true;

                    if let Some(w) = self.as_mut().early_waker.take() {
                        w.wake();
                    }
                    if let Some(w) = self.as_mut().flush_waker.take() {
                        w.wake();
                    }
                    return Poll::Ready(Ok(self.as_mut().early_data_len));
                } else {
                    let mut req = self.as_mut().req.take().expect("req must be present");
                    if let Some(v) = req
                        .headers_mut()
                        .get_mut(&self.as_mut().early_data_header_name)
                    {
                        self.as_mut().early_data_len =
                            cmp::min(self.as_mut().early_data_len, buf.len());
                        let header_value =
                            URL_SAFE_NO_PAD.encode(&buf[..self.as_mut().early_data_len]);
                        *v = HeaderValue::from_str(&header_value).expect("bad header value");
                    }

                    let stream = self.as_mut().stream.take().expect("msg: bad state");
                    let config = self.as_mut().ws_config.take();
                    self.as_mut().stream_future = Some(Self::proxy_stream(stream, req, config));
                }
            }
        }

        match &mut self.as_mut().stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.early_data_flushed {
            if self.as_mut().flush_waker.is_none() {
                self.as_mut().flush_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        match &mut self.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if !self.early_data_flushed {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        let pin = self.get_mut();
        match &mut pin.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
