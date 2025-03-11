use bytes::{Buf as _, BufMut};
use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::io::{AsyncRead, AsyncReadExt};
use watfaq_types::{SocksAddrType, TargetAddr};
// TODO
// There are some helper functions which shouldn't be here
pub trait TargetAddrExt: Sized {
    fn write_buf<T: BufMut>(&self, buf: &mut T);
    fn write_to_buf_vmess<B: BufMut>(&self, buf: &mut B);
    fn size(&self) -> usize;
    fn peek_read(buf: &[u8]) -> std::io::Result<Self>;
    fn read_from<T: AsyncRead + Unpin>(
        r: &mut T,
    ) -> impl Future<Output = io::Result<Self>>;
    fn from_slice(buf: &[u8]) -> io::Result<Self>;
}

impl TargetAddrExt for TargetAddr {
    // TODO move to vmess
    fn write_buf<T: BufMut>(&self, buf: &mut T) {
        match self {
            Self::Socket(addr) => match addr {
                SocketAddr::V4(addr) => {
                    buf.put_u8(SocksAddrType::V4);
                    buf.put_slice(&addr.ip().octets());
                    buf.put_u16(addr.port());
                }
                SocketAddr::V6(addr) => {
                    buf.put_u8(SocksAddrType::V6);
                    buf.put_slice(&addr.ip().octets());
                    buf.put_u16(addr.port());
                }
            },
            Self::Domain(domain, port) => {
                buf.put_u8(SocksAddrType::DOMAIN);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
        }
    }

    fn write_to_buf_vmess<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::Socket(SocketAddr::V4(addr)) => {
                buf.put_u16(addr.port());
                buf.put_u8(0x01);
                buf.put_slice(&addr.ip().octets());
            }
            Self::Socket(SocketAddr::V6(addr)) => {
                buf.put_u16(addr.port());
                buf.put_u8(0x03);
                for seg in &addr.ip().segments() {
                    buf.put_u16(*seg);
                }
            }
            Self::Domain(domain_name, port) => {
                buf.put_u16(*port);
                buf.put_u8(0x02);
                buf.put_u8(domain_name.len() as u8);
                buf.put_slice(domain_name.as_bytes());
            }
        }
    }

    fn size(&self) -> usize {
        match self {
            // SOCKS5 ATYP
            TargetAddr::Socket(ip) => match ip {
                SocketAddr::V4(_) => 1 + 4 + 2, // ATYP + IPv4 len + port len
                SocketAddr::V6(_) => 1 + 16 + 2,
            },
            TargetAddr::Domain(domain, _) => 1 + 1 + domain.len() + 2,
        }
    }

    fn peek_read(buf: &[u8]) -> io::Result<Self> {
        let mut cur = std::io::Cursor::new(buf);
        peek_cursor(&mut cur)
    }

    async fn read_from<T: AsyncRead + Unpin>(r: &mut T) -> io::Result<Self> {
        match r.read_u8().await? {
            SocksAddrType::V4 => {
                let ip = Ipv4Addr::from(r.read_u32().await?);
                let port = r.read_u16().await?;
                Ok(Self::Socket((ip, port).into()))
            }
            SocksAddrType::V6 => {
                let ip = Ipv6Addr::from(r.read_u128().await?);
                let port = r.read_u16().await?;
                Ok(Self::Socket((ip, port).into()))
            }
            SocksAddrType::DOMAIN => {
                let domain_len = r.read_u8().await? as usize;
                let mut buf = vec![0u8; domain_len];
                let n = r.read_exact(&mut buf).await?;
                if n != domain_len {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "invalid domain length",
                    ));
                }
                let domain = String::from_utf8(buf).map_err(|_| invalid_domain())?;
                let port = r.read_u16().await?;
                Ok(Self::Domain(domain, port))
            }
            _ => Err(invalid_atyp()),
        }
    }

    fn from_slice(buf: &[u8]) -> io::Result<Self> {
        if buf.is_empty() {
            return Err(insuff_bytes());
        }

        match buf[0] {
            SocksAddrType::V4 => {
                if buf.len() < 1 + 4 + 2 {
                    // ATYP + DST.ADDR + DST.PORT
                    return Err(insuff_bytes());
                }

                let mut ip_bytes = [0u8; 4];
                ip_bytes.copy_from_slice(&buf[1..5]);
                let ip = Ipv4Addr::from(ip_bytes);
                let mut port_bytes = [0u8; 2];
                port_bytes.copy_from_slice(&buf[5..7]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Socket((ip, port).into()))
            }

            SocksAddrType::V6 => {
                if buf.len() < 1 + 16 + 2 {
                    // ATYP + DST.ADDR + DST.PORT
                    return Err(insuff_bytes());
                }

                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(ip_bytes);
                let mut port_bytes = [0u8; 2];
                port_bytes.copy_from_slice(&buf[17..19]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Socket((ip, port).into()))
            }

            SocksAddrType::DOMAIN => {
                if buf.is_empty() {
                    return Err(insuff_bytes());
                }
                let domain_len = buf[1] as usize;
                if buf.len() < 1 + domain_len + 2 {
                    return Err(insuff_bytes());
                }
                let domain = String::from_utf8((buf[2..domain_len + 2]).to_vec())
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("invalid domain: {}", e),
                        )
                    })?;
                let mut port_bytes = [0u8; 2];
                (port_bytes).copy_from_slice(&buf[domain_len + 2..domain_len + 4]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Domain(domain, port))
            }

            _ => Err(io::Error::new(io::ErrorKind::Other, "invalid ATYP")),
        }
    }
}

#[inline]
fn peek_cursor<T: AsRef<[u8]>>(cur: &mut io::Cursor<T>) -> io::Result<TargetAddr> {
    if cur.remaining() < 2 {
        return Err(io::Error::new(io::ErrorKind::Other, "invalid buf"));
    }

    let atyp = cur.get_u8();
    match atyp {
        SocksAddrType::V4 => {
            if cur.remaining() < 4 + 2 {
                return Err(io::Error::new(io::ErrorKind::Other, "invalid buf"));
            }
            let addr = Ipv4Addr::from(cur.get_u32());
            let port = cur.get_u16();
            Ok(TargetAddr::Socket((addr, port).into()))
        }
        SocksAddrType::V6 => {
            if cur.remaining() < 16 + 2 {
                return Err(io::Error::new(io::ErrorKind::Other, "invalid buf"));
            }
            let addr = Ipv6Addr::from(cur.get_u128());
            let port = cur.get_u16();
            Ok(TargetAddr::Socket((addr, port).into()))
        }
        SocksAddrType::DOMAIN => {
            let domain_len = cur.get_u8() as usize;
            if cur.remaining() < domain_len {
                return Err(io::Error::new(io::ErrorKind::Other, "invalid buf"));
            }
            let mut buf = vec![0u8; domain_len];
            cur.copy_to_slice(&mut buf);
            let port = cur.get_u16();
            let domain_name =
                String::from_utf8(buf).map_err(|_x| invalid_domain())?;
            Ok(TargetAddr::Domain(domain_name, port))
        }
        _ => Err(invalid_atyp()),
    }
}

fn invalid_domain() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "invalid domain")
}

fn invalid_atyp() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "invalid address type")
}

fn insuff_bytes() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "insufficient bytes")
}
