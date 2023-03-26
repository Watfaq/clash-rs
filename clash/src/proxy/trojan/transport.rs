



use bytes::BufMut;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use bytes::Buf;
use bytes::BytesMut;
use futures_util::ready;

use crate::common::errors::new_io_error;
use crate::session::SocksAddr;




const CMD_TCP_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const HASH_STR_LEN: usize = 56;

/// ```plain
/// +-----------------------+---------+----------------+---------+----------+
/// | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
/// +-----------------------+---------+----------------+---------+----------+
/// |          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
/// +-----------------------+---------+----------------+---------+----------+
///
/// where Trojan Request is a SOCKS5-like request:
///
/// +-----+------+----------+----------+
/// | CMD | ATYP | DST.ADDR | DST.PORT |
/// +-----+------+----------+----------+
/// |  1  |  1   | Variable |    2     |
/// +-----+------+----------+----------+
///
/// where:
///
/// o  CMD
/// o  CONNECT X'01'
/// o  UDP ASSOCIATE X'03'
/// o  ATYP address type of following address
/// o  IP V4 address: X'01'
/// o  DOMAINNAME: X'03'
/// o  IP V6 address: X'04'
/// o  DST.ADDR desired destination address
/// o  DST.PORT desired destination port in network octet order
/// ```
#[derive(Clone)]
pub enum RequestHeader {
    TcpConnect([u8; HASH_STR_LEN], Address),
    UdpAssociate([u8; HASH_STR_LEN]),
}

impl RequestHeader {
    #[allow(dead_code)]
    pub async fn read_from<R>(
        stream: &mut R,
        valid_hash: &[u8],
        first_packet: &mut Vec<u8>,
    ) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut hash_buf = [0u8; HASH_STR_LEN];
        let len = stream.read(&mut hash_buf).await?;
        if len != HASH_STR_LEN {
            first_packet.extend_from_slice(&hash_buf[..len]);
            return Err(new_io_error("first packet too short"));
        }

        if valid_hash != hash_buf {
            first_packet.extend_from_slice(&hash_buf);
            return Err(new_io_error(format!(
                "invalid password hash: {}",
                String::from_utf8_lossy(&hash_buf)
            ).as_str()));
        }

        let mut crlf_buf = [0u8; 2];
        let mut cmd_buf = [0u8; 1];

        stream.read_exact(&mut crlf_buf).await?;
        stream.read_exact(&mut cmd_buf).await?;
        let addr = SocksAddr::read_from_stream(stream).await?;
        stream.read_exact(&mut crlf_buf).await?;

        match cmd_buf[0] {
            CMD_TCP_CONNECT => Ok(Self::TcpConnect(hash_buf, addr)),
            CMD_UDP_ASSOCIATE => Ok(Self::UdpAssociate(hash_buf)),
            _ => Err(new_io_error("invalid command")),
        }
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let udp_dummy_addr = SocksAddr::any_ipv4();
        let (hash, addr, cmd) = match self {
            RequestHeader::TcpConnect(hash, addr) => (hash, addr, CMD_TCP_CONNECT),
            RequestHeader::UdpAssociate(hash) => (hash, &udp_dummy_addr, CMD_UDP_ASSOCIATE),
        };

        let header_len = HASH_STR_LEN + 2 + 1 + addr.serialized_len() + 2;
        let mut buf = Vec::with_capacity(header_len);

        let cursor = &mut buf;
        let crlf = b"\r\n";
        cursor.put_slice(hash);
        cursor.put_slice(crlf);
        cursor.put_u8(cmd);
        addr.write_to_buf(cursor);
        cursor.put_slice(crlf);

        w.write_all(&buf).await?;
        Ok(())
    }
}

/// ```plain
/// +------+----------+----------+--------+---------+----------+
/// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
/// +------+----------+----------+--------+---------+----------+
/// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
/// +------+----------+----------+--------+---------+----------+
/// ```
pub struct TrojanUdpStream<T> {
    stream: T,
    reader: TrojanUdpReader,
    writer: TrojanUdpWriter,
}

impl<T> TrojanUdpStream<T> {
    pub fn new(stream: T) -> Self {
        Self {
            stream,
            reader: TrojanUdpReader::new(),
            writer: TrojanUdpWriter::new(),
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TrojanUdpStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        unimplemented!()
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TrojanUdpStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        unimplemented!()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.priv_poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.priv_poll_shutdown(cx)
    }
}

struct TrojanUdpReader {
    read_state: u32,
    addr: SocksAddr,
    buffer: BytesMut, // atyp + len domain + domain name + port + len(2) + 0D0A  <=259+2+2
    minimal_data_to_put: usize,
    read_res: Poll<io::Result<()>>, // for state machine generator
    data_length: usize,
    read_zero: bool,
}

impl TrojanUdpReader {
    fn new() -> Self {
        Self {
            read_state: 0,
            addr: SocksAddr::any_ipv4(),
            buffer: BytesMut::with_capacity(1024),
            minimal_data_to_put: 0,
            read_res: Poll::Pending,
            data_length: 0,
            read_zero: false,
        }
    }

    fn priv_poll_read<R>(
        &mut self,
        r: &mut R,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            self.read_res = co_await(self.read_at_least(r, cx, 2)); //atyp and (domain name length) Ip first byte
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            self.data_length = match self.buffer[0] {
                0x01 => 1 + 4 + 2 + 4,
                0x4 => 1 + 16 + 2 + 4,
                0x3 => 2 + self.buffer[1] as usize + 2 + 4,
                _ => {
                    return Err(std::io::Error::new(
                        io::ErrorKind::Other,
                        format!("not supported address type {:#x}", self.buffer[0]),
                    ))
                    .into();
                }
            };
            self.read_reserve(self.data_length);
            // 2. read data
            self.read_res = co_await(self.read_at_least(r, cx, self.data_length));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            self.addr = Address::read_from_buf(&self.buffer)?;
            self.buffer.advance(self.addr.serialized_len());
            self.data_length = self.buffer.get_u16() as usize;
            self.buffer.advance(2); // 0D0A (2bytes)
            self.read_reserve(self.data_length);
            self.read_res = co_await(self.read_at_least(r, cx, self.data_length));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            // 3. we have read adequate data
            while self.calc_data_to_put(dst) != 0 {
                dst.put_slice(&self.buffer.as_ref()[0..self.minimal_data_to_put]);
                self.data_length -= self.minimal_data_to_put;
                self.buffer.advance(self.minimal_data_to_put);
                co_yield(Poll::Ready(Ok(())));
            }
        }
    }

    fn take_addr(&mut self) -> SocksAddr {
        std::mem::take(&mut self.addr)
    }
}

struct TrojanUdpWriter {
    state: u32,
    buffer: BytesMut, // atyp + len domain + domain name + port + len(2) + 0D0A  <=259+2+2
    pos: usize,
    data_len: usize,
    write_res: Poll<io::Result<usize>>, // for state machine generator
}

impl TrojanUdpWriter {
    fn new() -> Self {
        Self {
            state: 0,
            buffer: BytesMut::with_capacity(259 + 2 + 2),
            pos: 0,
            data_len: 0,
            write_res: Poll::Pending,
        }
    }

    #[inline]
    fn write_data<W>(
        &mut self,
        w: &mut W,
        ctx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        while self.pos < buffer.len() {
            let n = ready!(Pin::new(&mut *w).poll_write(ctx, &buffer[self.pos..]))?;
            self.pos += n;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write zero byte into writer",
                )));
            }
        }
        Poll::Ready(Ok(self.data_len))
    }

    #[inline]
    fn write_buffer_data<W>(&mut self, w: &mut W, ctx: &mut Context<'_>) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        while self.pos < self.buffer.len() {
            let n = ready!(Pin::new(&mut *w).poll_write(ctx, &self.buffer[self.pos..]))?;
            self.pos += n;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write zero byte into writer",
                )));
            }
        }
        Poll::Ready(Ok(self.data_len))
    }

    fn priv_poll_write<W>(
        &mut self,
        w: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
        addr: &SocksAddr,
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        loop {
            self.data_len = data.len();
            if self.data_len == 0 {
                return Poll::Ready(Ok(0));
            }
            addr.write_buf(&mut self.buffer);
            self.buffer.put_u16(data.len() as u16);
            self.buffer.put_slice(b"\r\n");
            self.write_res = co_await(self.write_buffer_data(w, cx));
            self.pos = 0;
            self.buffer.clear();
            loop {
                self.write_res = self.write_data(w, cx, data);
                if self.write_res.is_ready() {
                    break;
                }
                co_yield(Poll::Pending);
            }
            self.pos = 0;
            co_yield(std::mem::replace(&mut self.write_res, Poll::Pending));
        }
    }
}