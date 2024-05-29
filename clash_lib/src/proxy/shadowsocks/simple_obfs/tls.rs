// a rust implementation of https://github.com/MetaCubeX/Clash.Meta/blob/Alpha/transport/simple-obfs/tls.go

use std::{
    borrow::Cow,
    pin::Pin,
    task::{Context, Poll},
};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use bytes::BufMut;
use chrono::Utc;
use futures::pin_mut;
use std::future::Future;
use std::task::ready;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::proxy::AnyStream;
const CHUNK_SIZE: isize = 1 << 14; // 2 ** 14 == 16 * 1024

#[derive(Debug)]
enum ReadState {
    Idle,
    Parsing,
    Reading(usize), // Length
}

#[derive(Debug)]
enum WriteState {
    Idle,
    Writing(usize, usize), // current, total
}

#[derive(Debug)]
pub struct TLSObfs {
    inner: AnyStream,
    server: String,
    remain: usize,
    first_request: bool,
    first_response: bool,
    read_state: ReadState,
    write_state: WriteState,
}

impl AsyncWrite for TLSObfs {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        loop {
            match this.write_state {
                WriteState::Idle => {
                    this.write_state = WriteState::Writing(0, buf.len());
                }
                WriteState::Writing(current, total) => {
                    let end = (current + CHUNK_SIZE as usize).min(total);
                    let chunk = &buf[current..end];
                    ready!(writing(Pin::new(this), chunk, cx))?;
                    if end == total {
                        this.write_state = WriteState::Idle;
                        return Poll::Ready(Ok(total));
                    } else {
                        this.write_state = WriteState::Writing(end, total);
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for TLSObfs {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        tracing::debug!("poll read");
        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);
        if this.remain > 0 {
            let length = this.remain.min(buf.remaining());
            ready!(inner.as_mut().poll_read(cx, buf))?;
            this.remain -= length;
            return Poll::Ready(Ok(()));
        }
        if this.first_response {
            tracing::debug!("poll read first response");
            // type + ver + lensize + 91 = 96
            // type + ver + lensize + 1 = 6
            // type + ver = 3
            ready!(reading(Pin::new(this), buf, cx, 105))?;
            this.first_response = false;
            return Poll::Ready(Ok(()));
        }

        // type + ver = 3
        ready!(reading(Pin::new(this), buf, cx, 3))?;
        tracing::debug!("poll read type and version");
        Poll::Ready(Ok(()))
    }
}

fn writing(
    this: std::pin::Pin<&mut TLSObfs>,
    b: &[u8],
    cx: &mut Context<'_>,
) -> Poll<Result<usize, std::io::Error>> {
    let this = this.get_mut();
    let inner = Pin::new(&mut this.inner);
    if this.first_request {
        let hello_msg = make_client_hello_msg(b, &this.server);
        match ready!(inner.poll_write(cx, &hello_msg)) {
            Ok(n) => {
                this.first_request = false;
                return Poll::Ready(Ok(n));
            }
            Err(e) => return Poll::Ready(Err(e)),
        }
    }
    let mut buf = Vec::new();
    buf.put_slice(&[0x17, 0x03, 0x03]);
    buf.write_u16::<BigEndian>(b.len() as u16).unwrap();
    buf.put_slice(b);
    inner.poll_write(cx, &buf)
}

fn reading(
    this: std::pin::Pin<&mut TLSObfs>,
    buf: &mut ReadBuf<'_>,
    cx: &mut Context<'_>,
    discard_n: usize,
) -> Poll<Result<(), std::io::Error>> {
    let this = this.get_mut();
    let mut inner = Pin::new(&mut this.inner);

    loop {
        match this.read_state {
            ReadState::Idle => {
                // 1. discard n bytes
                tracing::debug!("ReadState Idle");
                let mut buffer = vec![0; discard_n];
                let fut = inner.read_exact(&mut buffer);
                pin_mut!(fut);
                match ready!(fut.poll(cx)) {
                    Ok(_) => {
                        this.read_state = ReadState::Parsing;
                        tracing::debug!("ReadState Idle end");
                        continue;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
            ReadState::Parsing => {
                // 2. read 2 bytes as length
                tracing::debug!("ReadState Parsing");
                let mut buffer = vec![0; 2];
                let fut = inner.read_exact(&mut buffer);
                pin_mut!(fut);
                match ready!(fut.poll(cx)) {
                    Ok(_) => {
                        let length = BigEndian::read_u16(&buffer[..2]) as usize;
                        this.read_state = ReadState::Reading(length);
                        tracing::debug!("ReadState Parsing end");
                        continue;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
            ReadState::Reading(length) => {
                tracing::debug!("ReadState Reading");
                // 3. read length bytes
                let remaining = buf.remaining();
                let len = length.min(remaining);
                let mut buffer = vec![0; len];
                let fut = inner.read_exact(&mut buffer);
                pin_mut!(fut);
                match ready!(fut.poll(cx)) {
                    Ok(_) => {
                        buf.put_slice(&buffer);
                        if length > remaining {
                            this.remain = length - remaining;
                        }
                        this.read_state = ReadState::Idle;
                        tracing::debug!("ReadState Reading end");
                        return Poll::Ready(Ok(()))
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }
    }
}

fn make_client_hello_msg<'a>(data: &[u8], server: &str) -> Cow<'a, Vec<u8>> {
    let random_bytes = rand::random::<[u8; 28]>();
    let session_id = rand::random::<[u8; 32]>();

    let mut buf: Vec<u8> = Vec::new();

    // handshake, TLS 1.0 version, length
    buf.put_u8(22);
    buf.put_slice(&[0x03, 0x01]);
    let length: u16 = (212 + data.len() + server.len()) as u16;
    buf.put_u8((length >> 8) as u8);
    buf.put_u8((length & 0xff) as u8);

    // clientHello, length, TLS 1.2 version
    buf.put_u8(1);
    buf.put_u8(0);
    buf.write_u16::<BigEndian>((208 + data.len() + server.len()) as u16)
        .unwrap();
    buf.put_slice(&[0x03, 0x03]);

    // random with timestamp, sid len, sid
    buf.write_u32::<BigEndian>(Utc::now().timestamp() as u32)
        .unwrap();
    buf.put_slice(&random_bytes);
    buf.put_u8(32);
    buf.put_slice(&session_id);

    // cipher suites
    buf.put_slice(&[0x00, 0x38]);
    buf.put_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);

    // compression
    buf.put_slice(&[0x01, 0x00]);

    // extension length
    buf.write_u16::<BigEndian>((79 + data.len() + server.len()) as u16)
        .unwrap();

    // session ticket
    buf.put_slice(&[0x00, 0x23]);
    buf.write_u16::<BigEndian>(data.len() as u16).unwrap();
    buf.put_slice(data);

    // server name
    buf.put_slice(&[0x00, 0x00]);
    buf.write_u16::<BigEndian>((server.len() + 5) as u16)
        .unwrap();
    buf.write_u16::<BigEndian>((server.len() + 3) as u16)
        .unwrap();
    buf.put_u8(0);
    buf.write_u16::<BigEndian>(server.len() as u16).unwrap();
    buf.put_slice(server.as_bytes());

    // ec_point
    buf.put_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);

    // groups
    buf.put_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);

    // signature
    buf.put_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);

    // encrypt then mac
    buf.put_slice(&[0x00, 0x16, 0x00, 0x00]);

    // extended master secret
    buf.put_slice(&[0x00, 0x17, 0x00, 0x00]);
    Cow::Owned(buf)
}

impl TLSObfs {
    pub fn new(inner: AnyStream, server: String) -> Self {
        TLSObfs {
            inner,
            server,
            remain: 0,
            read_state: ReadState::Idle,
            write_state: WriteState::Idle,
            first_request: true,
            first_response: true,
        }
    }
}

impl From<TLSObfs> for AnyStream {
    fn from(obfs: TLSObfs) -> Self {
        Box::new(obfs)
    }
}
