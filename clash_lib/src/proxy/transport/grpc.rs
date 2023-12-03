use crate::common::errors::map_io_error;
use crate::proxy::AnyStream;

use bytes::Buf;
use bytes::{BufMut, Bytes, BytesMut};

use futures::ready;
use h2::{RecvStream, SendStream};
use http::{Request, Uri, Version};
use prost::encoding::decode_varint;
use prost::encoding::encode_varint;
use tokio::sync::{mpsc, Mutex};
use tracing::warn;
use tracing::{debug, trace};

use std::fmt::Debug;
use std::io;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone)]
pub struct GrpcStreamBuilder {
    pub host: String,
    pub path: http::uri::PathAndQuery,
}

impl GrpcStreamBuilder {
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

    pub async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let (client, h2) = h2::client::Builder::new()
            .enable_push(false)
            .handshake(stream)
            .await
            .map_err(map_io_error)?;
        let mut client = client.ready().await.map_err(map_io_error)?;

        let req = self.req()?;
        let (resp, send_stream) = client.send_request(req, false).map_err(map_io_error)?;
        tokio::spawn(async move {
            if let Err(e) = h2.await {
                //TODO: collect this somewhere?
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
                        debug!("grpc resp: {:?}", resp);
                        recv_stream.lock().await.replace(resp.into_body());
                    }
                    Err(e) => {
                        debug!("grpc resp err: {:?}", e);
                    }
                }
                let _ = init_sender.send(());
            });
        }

        return Ok(Box::new(GrpcStream::new(
            init_ready,
            recv_stream,
            send_stream,
        )));
    }
}

pub struct GrpcStream {
    init_ready: mpsc::Receiver<()>,
    recv: Arc<Mutex<Option<RecvStream>>>,
    send: SendStream<Bytes>,
    buffer: BytesMut,
    payload_len: u64,
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

    fn encode_buf(&self, data: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(16 + data.len());
        let grpc_header = [0u8; 5];
        buf.put_slice(&grpc_header[..]);
        buf.put_u8(0x0a);
        encode_varint(data.len() as u64, &mut buf);
        let payload_len = ((buf.len() - 5 + data.len()) as u32).to_be_bytes();
        buf[1..5].copy_from_slice(&payload_len[..4]);
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
        trace!("grpc poll_read: {:?}", buf);

        ready!(self.init_ready.poll_recv(cx));

        let recv = self.recv.clone();

        let mut recv = recv.try_lock().unwrap();
        if recv.is_none() {
            trace!("initialization error");
            return Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionReset,
                "initialization error",
            )));
        }

        if self.payload_len > 0 {
            trace!("grpc poll_read data left payload_len: {}", self.payload_len);
            let to_read = std::cmp::min(buf.remaining(), self.payload_len as usize);
            let data = self.buffer.split_to(to_read);
            self.payload_len -= to_read as u64;
            buf.put_slice(&data[..to_read]);
            return Poll::Ready(Ok(()));
        };

        trace!(
            "no decoded data left, grpc poll_read data left buffer: {}",
            self.buffer.len()
        );

        Poll::Ready(
            match ready!(Pin::new(&mut recv.as_mut().unwrap()).poll_data(cx)) {
                Some(Ok(b)) => {
                    let mut data = BytesMut::with_capacity(self.buffer.len() + b.len());
                    data.extend_from_slice(&self.buffer[..]);
                    data.extend_from_slice(&b[..]);
                    self.buffer.clear();

                    while self.payload_len > 0 || data.len() > 6 {
                        if self.payload_len == 0 {
                            data.advance(6);
                            self.payload_len = decode_varint(&mut data).map_err(map_io_error)?;
                        }
                        let to_read = std::cmp::min(buf.remaining(), data.len());
                        let to_read = std::cmp::min(self.payload_len as usize, to_read);
                        if to_read == 0 {
                            self.buffer.extend_from_slice(&data[..]);
                            data.clear();
                            break;
                        }
                        buf.put_slice(&data[..to_read]);
                        self.payload_len -= to_read as u64;
                        data.advance(to_read);
                    }

                    trace!("released grpc flow control capacity: {}", b.len());
                    recv.as_mut()
                        .unwrap()
                        .flow_control()
                        .release_capacity(b.len())
                        .map_or_else(
                            |e| {
                                debug!("grpc flow control error: {}", e);
                                Err(Error::new(ErrorKind::ConnectionReset, e))
                            },
                            |_| Ok(()),
                        )
                }
                _ => Ok(()),
            },
        )
    }
}

impl AsyncWrite for GrpcStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        trace!("grpc poll_write: {:?}", buf.len());

        let encoded_buf = self.encode_buf(buf);
        trace!("requesting capacity: {} bytes", encoded_buf.len());
        self.send.reserve_capacity(encoded_buf.len());

        Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(cap)) => {
                trace!("grpc got capacity: {} bytes", cap);
                let overhead_len = encoded_buf.len() - buf.len();
                self.send.send_data(encoded_buf, false).map_or_else(
                    |e| {
                        debug!("grpc write error: {}", e);
                        Err(Error::new(ErrorKind::BrokenPipe, e))
                    },
                    |_| Ok(cap - overhead_len),
                )
            }
            Some(Err(e)) => {
                warn!("grpc poll_capacity error: {}", e);
                Err(Error::new(ErrorKind::BrokenPipe, e))
            }
            _ => {
                debug!("grpc poll_capacity conn closed");
                Err(Error::new(ErrorKind::BrokenPipe, "broken pipe"))
            }
        })
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.send_reset(h2::Reason::NO_ERROR);
        self.send
            .poll_reset(cx)
            .map_err(map_io_error)
            .map(|_| Ok(()))
    }
}
