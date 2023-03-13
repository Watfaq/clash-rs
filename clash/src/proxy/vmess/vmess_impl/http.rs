use std::{collections::HashMap, io, pin::Pin};

use bytes::{BytesMut, BufMut};
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, BufStream, ReadBuf};

use crate::{
    common::{errors::map_io_error, utils},
    proxy::AnyStream,
};

pub struct HttpConfig {
    pub method: String,
    pub host: String,
    pub path: Vec<String>,
    pub headers: HashMap<String, String>,
}

impl HttpConfig {
    pub fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let idx = utils::rand_range(0..self.path.len());
        let path = self.path[idx].clone();
        Ok(Box::new(HttpStream::new(
            stream,
            self.host.clone(),
            path,
            self.headers.clone(),
        )))
    }
}

pub struct HttpStream {
    bufio: BufStream<AnyStream>,
    host: String,
    path: String,
    headers: HashMap<String, String>,
    buf: BytesMut,
    header_consumed: bool,
    header_sent: bool,
}

impl HttpStream {
    pub fn new(
        stream: AnyStream,
        host: String,
        path: String,
        headers: HashMap<String, String>,
    ) -> Self {
        Self {
            bufio: BufStream::new(stream),
            host,
            path,
            headers,
            buf: BytesMut::with_capacity(16),
            header_consumed: false,
            header_sent: false,
        }
    }
}

impl AsyncRead for HttpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let Self {
            bufio,
            buf: read_buf,
            header_consumed,
            ..
        } = self.get_mut();
        let mut pin = Pin::new(bufio);

        if !*header_consumed {
            let mut headers = [httparse::EMPTY_HEADER; 0];
            let mut req = httparse::Request::new(&mut headers);
            let mut header_buf = BytesMut::with_capacity(1024);
            while req.parse(&header_buf).map_err(map_io_error)?.is_partial() {
                let mut read_buf = ReadBuf::new(read_buf);
                ready!(pin.as_mut().poll_read(cx, &mut read_buf))?;
                header_buf.extend_from_slice(read_buf.filled());
            }

            *header_consumed = true;

            let offset = req.parse(&header_buf).map_err(map_io_error)?.unwrap();
            let body = &header_buf[offset..];

            if body.len() < buf.remaining() {
                buf.put_slice(body);
                return std::task::Poll::Ready(Ok(()));
            } else {
                buf.put_slice(&body[..buf.remaining()]);
                read_buf.reserve(body.len() - buf.remaining());
                read_buf.clone_from_slice(&body[buf.remaining()..]);
                return std::task::Poll::Ready(Ok(()));
            }
        } else {
            if !read_buf.is_empty() {
                let to_read = std::cmp::min(read_buf.len(), buf.remaining());
                let data = read_buf.split_to(to_read);
                buf.put_slice(&data[..to_read]);
                return std::task::Poll::Ready(Ok(()));
            }

            pin.poll_read(cx, buf)
        }
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let Self {
            bufio,
            buf: write_buf,
            header_sent,
            ..
        } = self.get_mut();

        if !*header_sent {
            let mut req = BytesMut::new();
            let req_line = format!("GET {} HTTP/1.1\r\n", self.path);
            req.reserve(req_line.len());
            req.put_slice(req_line.as_bytes());

            let header_line = format!("Host: {}\r\n", self.host);
            req.reserve(header_line.len());
            req.put_slice(header_line.as_bytes());

            for (k, v) in self.headers.iter() {
                let header_line = format!("{}: {}\r\n", k, v);
                req.reserve(header_line.len());
                req.put_slice(header_line.as_bytes());
            }

            req.put_slice(buf);

            let result = Pin::new(&mut *bufio).poll_write(cx, req.as_ref());

            *header_sent = true;
            result
        } else {
            Pin::new(bufio).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let Self { bufio, .. } = self.get_mut();
        Pin::new(&mut bufio).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let Self { bufio, .. } = self.get_mut();
        Pin::new(&mut bufio).poll_shutdown(cx)
    }
}
