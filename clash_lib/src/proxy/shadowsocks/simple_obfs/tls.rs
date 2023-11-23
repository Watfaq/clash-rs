// a rust implementation of https://github.com/MetaCubeX/Clash.Meta/blob/Alpha/transport/simple-obfs/tls.go

use std::{borrow::Cow, pin::Pin};

use byteorder::{BigEndian, WriteBytesExt};
use bytes::BufMut;
use chrono::Utc;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proxy::AnyStream;
const chunkSize: isize = 1 << 14; // 2 ** 14 == 16 * 1024

pub struct TLSObfs {
    inner: AnyStream,
    server: String,
    remain: i64,
    first_packet_recv: bool,
    first_packet_sent: bool,
}

impl AsyncWrite for TLSObfs {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        ctx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        todo!()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        todo!()
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        todo!()
    }
}

impl AsyncRead for TLSObfs {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        todo!()
    }
}

impl TLSObfs {
    fn make_client_hello_msg(self: std::pin::Pin<&mut Self>, data: &[u8]) -> Vec<u8> {
        let random_bytes = rand::random::<[u8; 28]>();
        let session_id = rand::random::<[u8; 32]>();

        let mut buf: Vec<u8> = Vec::new();

        // handshake, TLS 1.0 version, length
        buf.put_u8(22);
        buf.put_slice(&[0x03, 0x01]);
        let length: u16 = (212 + data.len() + self.server.len()) as u16;
        buf.put_u8((length >> 8) as u8);
        buf.put_u8((length & 0xff) as u8);

        // clientHello, length, TLS 1.2 version
        buf.put_u8(1);
        buf.put_u8(0);
        buf.write_u16::<BigEndian>((208 + data.len() + self.server.len()) as u16)
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
            0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b,
            0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27,
            0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33,
            0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
        ]);

        // compression
        buf.put_slice(&[0x01, 0x00]);

        // extension length
        buf.write_u16::<BigEndian>((79 + data.len() + self.server.len()) as u16)
            .unwrap();

        // session ticket
        buf.put_slice(&[0x00, 0x23]);
        buf.write_u16::<BigEndian>(data.len() as u16).unwrap();
        buf.put_slice(data);

        // server name
        buf.put_slice(&[0x00, 0x00]);
        buf.write_u16::<BigEndian>((self.server.len() + 5) as u16)
            .unwrap();
        buf.write_u16::<BigEndian>((self.server.len() + 3) as u16)
            .unwrap();
        buf.put_u8(0);
        buf.write_u16::<BigEndian>(self.server.len() as u16)
            .unwrap();
        buf.put_slice(self.server.as_bytes());

        // ec_point
        buf.put_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);

        // groups
        buf.put_slice(&[
            0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
        ]);

        // signature
        buf.put_slice(&[
            0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01,
            0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02,
            0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
        ]);

        // encrypt then mac
        buf.put_slice(&[0x00, 0x16, 0x00, 0x00]);

        // extended master secret
        buf.put_slice(&[0x00, 0x17, 0x00, 0x00]);
        buf
    }
}
