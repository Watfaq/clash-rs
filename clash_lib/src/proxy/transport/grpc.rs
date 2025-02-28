use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::ready;
use h2::{RecvStream, SendStream};
use http::{Request, Uri, Version};
use prost::encoding::{decode_varint, encode_varint};
use std::{
    fmt::Debug,
    io,
    io::{Error, ErrorKind},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, mpsc},
};
use tracing::warn;

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

#[derive(Clone)]
pub struct Client {
    pub host: String,
    pub path: http::uri::PathAndQuery,
}

impl Client {
    pub fn new(host: String, path: http::uri::PathAndQuery) -> Self {
        Self { host, path }
    }

    fn req(&self) -> io::Result<Request<()>> {
        let uri: Uri = {
            Uri::builder()
                .scheme("https")
                .authority(self.host.as_str())
                .path_and_query(format!("/{}/Tun", self.path.as_str()))
                .build()
                .map_err(map_io_error)?
        };
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .version(Version::HTTP_2)
            .header("content-type", "application/grpc")
            .header("user-agent", "tonic/0.10");
        Ok(request.body(()).unwrap())
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let (client, h2) = h2::client::Builder::new()
            .initial_connection_window_size(0x7FFFFFFF)
            .initial_window_size(0x7FFFFFFF)
            .initial_max_send_streams(1024)
            .enable_push(false)
            .handshake(stream)
            .await
            .map_err(map_io_error)?;
        let mut client = client.ready().await.map_err(map_io_error)?;

        let req = self.req()?;
        let (resp, send_stream) =
            client.send_request(req, false).map_err(map_io_error)?;
        tokio::spawn(async move {
            if let Err(e) = h2.await {
                // TODO: collect this somewhere?
                warn!("http2 got err:{:?}", e);
            }
        });

        let (init_sender, init_ready) = mpsc::channel(1);
        let recv_stream = Arc::new(Mutex::new(None));

        {
            let recv_stream = recv_stream.clone();
            tokio::spawn(async move {
                match resp.await {
                    Ok(resp) => {
                        match resp.status() {
                            http::StatusCode::OK => {}
                            _ => {
                                warn!(
                                    "grpc handshake resp err: {:?}",
                                    resp.into_body().data().await
                                );
                                return;
                            }
                        }
                        let stream = resp.into_body();
                        recv_stream.lock().await.replace(stream);
                    }
                    Err(e) => {
                        warn!("grpc resp err: {:?}", e);
                    }
                }
                let _ = init_sender.send(()).await;
            });
        }

        Ok(Box::new(GrpcStream::new(
            init_ready,
            recv_stream,
            send_stream,
        )))
    }
}

pub struct GrpcStream {
    init_ready: mpsc::Receiver<()>,
    recv: Arc<Mutex<Option<RecvStream>>>,
    send: SendStream<Bytes>,
    buffer: BytesMut,
    payload_len: usize,
}

impl Debug for GrpcStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcStream")
            .field("send", &self.send)
            .field("buffer", &self.buffer)
            .field("payload_len", &self.payload_len)
            .finish()
    }
}

impl GrpcStream {
    pub fn new(
        init_ready: mpsc::Receiver<()>,
        recv: Arc<Mutex<Option<RecvStream>>>,
        send: SendStream<Bytes>,
    ) -> Self {
        Self {
            init_ready,
            recv,
            send,
            buffer: BytesMut::with_capacity(1024 * 4),
            payload_len: 0,
        }
    }

    // encode data to grpc + protobuf format
    fn encode_buf(&self, data: &[u8]) -> Bytes {
        let mut protobuf_header = BytesMut::with_capacity(10 + 1);
        protobuf_header.put_u8(0x0a);
        encode_varint(data.len() as u64, &mut protobuf_header);
        let mut grpc_header = [0u8; 5];
        let grpc_payload_len = (protobuf_header.len() + data.len()) as u32;
        grpc_header[1..5].copy_from_slice(&grpc_payload_len.to_be_bytes());

        let mut buf = BytesMut::with_capacity(
            grpc_header.len() + protobuf_header.len() + data.len(),
        );
        buf.put_slice(&grpc_header[..]);
        buf.put_slice(&protobuf_header.freeze()[..]);
        buf.put_slice(data);
        buf.freeze()
    }
}

impl AsyncRead for GrpcStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.init_ready.poll_recv(cx));

        let recv = self.recv.clone();

        let mut recv = recv.try_lock().unwrap();
        if recv.is_none() {
            warn!("grpc initialization error");
            return Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionReset,
                "initialization error",
            )));
        }

        if (self.payload_len > 0 && !self.buffer.is_empty())
            || (self.payload_len == 0 && self.buffer.len() > 6)
        {
            if self.payload_len == 0 {
                self.buffer.advance(6);
                let payload_len =
                    decode_varint(&mut self.buffer).map_err(map_io_error)?;
                self.payload_len = payload_len as usize;
            }

            let to_read = std::cmp::min(buf.remaining(), self.payload_len);
            let to_read = std::cmp::min(to_read, self.buffer.len());

            if to_read == 0 {
                assert!(buf.remaining() > 0);

                return Poll::Pending;
            }

            let data = self.buffer.split_to(to_read);

            self.payload_len -= to_read;
            buf.put_slice(&data[..]);
            return Poll::Ready(Ok(()));
        }

        match ready!(Pin::new(&mut recv.as_mut().unwrap()).poll_data(cx)) {
            Some(Ok(b)) => {
                self.buffer.reserve(b.len());
                self.buffer.extend_from_slice(&b[..]);

                while self.payload_len > 0 || self.buffer.len() > 6 {
                    if self.payload_len == 0 {
                        self.buffer.advance(6);
                        let payload_len =
                            decode_varint(&mut self.buffer).map_err(map_io_error)?;
                        self.payload_len = payload_len as usize;
                    }
                    let to_read = std::cmp::min(self.buffer.len(), self.payload_len);
                    let to_read = std::cmp::min(buf.remaining(), to_read);
                    if to_read == 0 {
                        break;
                    }

                    buf.put_slice(self.buffer.split_to(to_read).freeze().as_ref());
                    self.payload_len -= to_read;
                }

                recv.as_mut()
                    .unwrap()
                    .flow_control()
                    .release_capacity(b.len())
                    .map_or_else(
                        |e| {
                            Poll::Ready(Err(Error::new(
                                ErrorKind::ConnectionReset,
                                e,
                            )))
                        },
                        |_| Poll::Ready(Ok(())),
                    )
            }
            _ => {
                assert_eq!(self.payload_len, 0);
                if recv.as_mut().unwrap().is_end_stream() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let encoded_buf = self.encode_buf(buf);

        self.send.reserve_capacity(encoded_buf.len());

        Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(_)) => self.send.send_data(encoded_buf, false).map_or_else(
                |e| {
                    warn!("grpc write error: {}", e);
                    Err(Error::new(ErrorKind::BrokenPipe, e))
                },
                |_| Ok(buf.len()),
            ),
            Some(Err(e)) => {
                warn!("grpc poll_capacity error: {}", e);
                Err(Error::new(ErrorKind::BrokenPipe, e))
            }
            _ => Err(Error::new(ErrorKind::BrokenPipe, "broken pipe")),
        })
    }

    #[inline]
    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.send.send_reset(h2::Reason::NO_ERROR);
        self.send
            .poll_reset(cx)
            .map_err(map_io_error)
            .map(|_| Ok(()))
    }
}
