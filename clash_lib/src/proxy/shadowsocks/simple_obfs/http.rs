use std::pin::Pin;

use base64::Engine;
// use hyper::Request;
use crate::proxy::AnyStream;
use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncWrite};
//
// static const char *http_request_template =
// "%s %s HTTP/1.1\r\n"
// "Host: %s\r\n"
// "User-Agent: curl/7.%d.%d\r\n"
// "Upgrade: websocket\r\n"
// "Connection: Upgrade\r\n"
// "Sec-WebSocket-Key: %s\r\n"
// "Content-Length: %lu\r\n"
// "\r\n";
//
// fn dump_request<T>(req: Request<T>) -> Vec<u8>
// where
//     T: Into<Vec<u8>>,
// {
//     tracing::debug!("{:?}", req.into_parts().0.);
//     let mut buf = Vec::new();
//     tracing::trace!("req: {:?}", format!(
//         "{} {} HTTP/1.1",
//         req.method().as_str(),
//         req.uri().path_and_query().unwrap()
//     ));
//     buf.extend_from_slice(
//         format!(
//             "{} {} HTTP/1.1",
//             req.method().as_str(),
//             req.uri().path_and_query().unwrap()
//         )
//         .as_bytes(),
//     );
//     buf.extend_from_slice(b"\r\n");
//     for (k, v) in req.headers() {
//         tracing::trace!("req: {:?}: {:?}", k, v);
//         buf.extend_from_slice(k.as_str().as_bytes());
//         buf.extend_from_slice(b": ");
//         buf.extend_from_slice(v.as_bytes());
//         buf.extend_from_slice(b"\r\n");
//     }
//     buf.extend_from_slice(b"\r\n");
//     let mut body: Vec<u8> = req.into_body().into();
//     buf.append(body.as_mut());
//     buf
// }

#[derive(Debug)]
pub struct HTTPObfs {
    inner: AnyStream,
    host: String,
    port: u16,
    // buf: Option<Vec<u8>>,
    // offset: usize,
    first_request: bool,
    first_response: bool,
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
            // let mut req = Request::builder()
            //     .method("GET")
            //     .uri(if pin.port == 80 {
            //         format!("http://{}/", pin.host)
            //     } else {
            //         format!("http://{}:{}", pin.host, pin.port)
            //     })
            //     .body(buf)
            //     .unwrap();
            // req.headers_mut().insert(
            //     "User-Agent",
            //     format!(
            //         "curl/7.{}.{}",
            //         rand::random::<isize>() % 54,
            //         rand::random::<isize>() % 2
            //     )
            //     .parse()
            //     .unwrap(),
            // );
            // req.headers_mut()
            //     .insert("Upgrade", "websocket".parse().unwrap());
            // req.headers_mut()
            //     .insert("Connection", "Upgrade".parse().unwrap());
            // req.headers_mut().insert(
            //     "Host",
            //     if pin.port != 80 {
            //         format!("{}:{}", pin.host, pin.port)
            //     } else {
            //         pin.host.clone()
            //     }
            //     .parse()
            //     .unwrap(),
            // );
            // req.headers_mut()
            //     .insert("Content-Length", buf.len().to_string().parse().unwrap());
            // req.headers_mut().insert(
            //     "Sec-WebSocket-Key",
            //     base64::engine::general_purpose::STANDARD
            //         .encode(rand_bytes)
            //         .parse()
            //         .unwrap(),
            // );

            // let req = dump_request(req);
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
        // if let Some(b) = &mut pin.buf {
        //     let n = b.len() - pin.offset;
        //     buf.filled_mut().copy_from_slice(&b[pin.offset..]);
        //     pin.offset += n;
        //     if pin.offset == b.len() {
        //         pin.buf = None;
        //         // pin.offset = 0;
        //     }
        //     return std::task::Poll::Ready(Ok(()));
        // }
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
                            // let length = b.filled().len() - idx + 4;
                            buf.put_slice(&b.filled()[idx + 4..b.filled().len()]);
                            std::task::Poll::Ready(Ok(()))
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
            // buf: None,
            // offset: 0,
            first_request: true,
            first_response: true,
        }
    }
}

impl From<HTTPObfs> for AnyStream {
    fn from(obfs: HTTPObfs) -> Self {
        Box::new(obfs)
    }
}
