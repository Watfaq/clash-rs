use std::pin::Pin;

use base64::Engine;
use hyper::Request;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proxy::AnyStream;

fn dump_request<T>(req: Request<T>) -> Vec<u8>
where
    T: Into<Vec<u8>>,
{
    let mut buf = Vec::new();
    buf.extend_from_slice(req.method().as_str().as_bytes());
    buf.extend_from_slice(b"\r\n");
    for (k, v) in req.headers() {
        buf.extend_from_slice(k.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(v.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    let mut body: Vec<u8> = req.into_body().into();
    buf.append(body.as_mut());
    buf
}

pub struct HTTPObfs {
    inner: AnyStream,
    host: String,
    port: u16,
    first_packet_sent: bool,
    first_packet_recv: bool,
}

impl AsyncWrite for HTTPObfs {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let pin = self.get_mut();
        if !pin.first_packet_sent {
            let rand_bytes = rand::random::<[u8; 16]>();
            let mut req = Request::builder()
                .method("GET")
                .uri(if pin.port == 80 {
                    format!("http://{}/", pin.host)
                } else {
                    format!("http://{}:{}", pin.host, pin.port)
                })
                .body(buf)
                .unwrap();
            req.headers_mut().insert(
                "User-Agent",
                format!("curl/7.{}.{}", rand::random::<i32>(), rand::random::<i32>())
                    .parse()
                    .unwrap(),
            );
            req.headers_mut()
                .insert("Upgrade", "websocket".parse().unwrap());
            req.headers_mut()
                .insert("Connection", "Upgrade".parse().unwrap());
            req.headers_mut()
                .insert("Content-Length", buf.len().to_string().parse().unwrap());
            req.headers_mut().insert(
                "Sec-WebSocket-Key",
                base64::engine::general_purpose::STANDARD
                    .encode(&rand_bytes)
                    .parse()
                    .unwrap(),
            );

            let req = dump_request(req);
            pin.first_packet_sent = true;
            Pin::new(&mut pin.inner).poll_write(cx, &req)
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
        if !pin.first_packet_recv {
            match Pin::new(&mut pin.inner).poll_read(cx, buf) {
                std::task::Poll::Ready(rv) => match rv {
                    Ok(_) => {
                        let needle = b"\r\n\r\n";
                        if buf
                            .filled()
                            .windows(needle.len())
                            .any(|window| window == needle)
                        {
                            std::task::Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "EOF",
                            )))
                        } else {
                            pin.first_packet_recv = true;
                            std::task::Poll::Ready(Ok(()))
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
