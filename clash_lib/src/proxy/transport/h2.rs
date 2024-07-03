use std::{collections::HashMap, fmt::Debug};

use bytes::{Bytes, BytesMut};
use futures::ready;
use h2::{RecvStream, SendStream};
use http::Request;
use rand::random;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::error;

use crate::{common::errors::map_io_error, proxy::AnyStream};

#[derive(Clone)]
pub struct Http2Config {
    pub hosts: Vec<String>,
    pub headers: HashMap<String, String>,
    pub method: http::Method,
    pub path: http::uri::PathAndQuery,
}

impl Http2Config {
    fn req(&self) -> std::io::Result<Request<()>> {
        let uri_idx = random::<usize>() % self.hosts.len();
        let uri = {
            http::Uri::builder()
                .scheme("https")
                .authority(self.hosts[uri_idx].as_str())
                .path_and_query(self.path.clone())
                .build()
                .map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                })?
        };
        let mut request = Request::builder()
            .uri(uri)
            .method(self.method.clone())
            .version(http::Version::HTTP_2);
        for (k, v) in self.headers.iter() {
            if k != "Host" {
                request = request.header(k, v);
            }
        }

        Ok(request.body(()).expect("build req"))
    }

    pub async fn proxy_stream(
        &self,
        stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        let (mut client, h2) =
            h2::client::handshake(stream).await.map_err(map_io_error)?;
        let req = self.req()?;
        let (resp, send_stream) =
            client.send_request(req, false).map_err(map_io_error)?;
        tokio::spawn(async move {
            if let Err(e) = h2.await {
                error!("h2 error: {}", e);
            }
        });

        let recv_stream = resp.await.map_err(map_io_error)?.into_body();

        Ok(Box::new(Http2Stream::new(recv_stream, send_stream)))
    }
}

pub struct Http2Stream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    buffer: BytesMut,
}

impl Debug for Http2Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2Stream")
            .field("recv", &self.recv)
            .field("send", &self.send)
            .field("buffer", &self.buffer)
            .finish()
    }
}

impl Http2Stream {
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            buffer: BytesMut::with_capacity(1024 * 4),
        }
    }
}

impl AsyncRead for Http2Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.buffer.is_empty() {
            let to_read = std::cmp::min(self.buffer.len(), buf.remaining());
            let data = self.buffer.split_to(to_read);
            buf.put_slice(&data[..to_read]);
            return std::task::Poll::Ready(Ok(()));
        }
        std::task::Poll::Ready(match ready!(self.recv.poll_data(cx)) {
            Some(Ok(data)) => {
                let to_read = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_read]);
                if to_read < data.len() {
                    self.buffer.extend_from_slice(&data[to_read..]);
                }
                self.recv
                    .flow_control()
                    .release_capacity(to_read)
                    .map_or_else(
                        |e| {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                e,
                            ))
                        },
                        |_| Ok(()),
                    )
            }
            _ => Ok(()),
        })
    }
}

impl AsyncWrite for Http2Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.send.reserve_capacity(buf.len());
        std::task::Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(to_write)) => self
                .send
                .send_data(Bytes::from(buf[..to_write].to_owned()), false)
                .map_or_else(
                    |e| Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)),
                    |_| Ok(to_write),
                ),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            )),
        })
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.send.reserve_capacity(0);
        std::task::Poll::Ready(ready!(self.send.poll_capacity(cx)).map_or(
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            )),
            |_| {
                self.send.send_data(Bytes::new(), true).map_or_else(
                    |e| Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)),
                    |_| Ok(()),
                )
            },
        ))
    }
}
