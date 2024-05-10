use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::proxy::utils::Interface;
use bytes::{Buf, BufMut};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt};

use erased_serde::Serialize as ESerialize;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Display for SocksAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SocksAddr::Ip(ip) => ip.to_string(),
                SocksAddr::Domain(host, port) => format!("{}:{}", host, port),
            }
        )
    }
}

pub struct SocksAddrType;

impl SocksAddrType {
    pub const V4: u8 = 0x1;
    pub const DOMAIN: u8 = 0x3;
    pub const V6: u8 = 0x4;
}

impl SocksAddr {
    pub fn any_ipv4() -> Self {
        Self::Ip("0.0.0.0:0".parse().unwrap())
    }

    pub fn any_ipv6() -> Self {
        Self::Ip("[::]:0".parse().unwrap())
    }

    pub fn write_buf<T: BufMut>(&self, buf: &mut T) {
        match self {
            Self::Ip(addr) => match addr {
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

    pub fn write_to_buf_vmess<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::Ip(SocketAddr::V4(addr)) => {
                buf.put_u16(addr.port());
                buf.put_u8(0x01);
                buf.put_slice(&addr.ip().octets());
            }
            Self::Ip(SocketAddr::V6(addr)) => {
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

    pub fn is_domain(&self) -> bool {
        match self {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(_, _) => true,
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            SocksAddr::Ip(_) => None,
            SocksAddr::Domain(domain, _) => Some(domain.as_str()),
        }
    }

    pub fn must_into_socket_addr(self) -> SocketAddr {
        match self {
            SocksAddr::Ip(addr) => addr,
            SocksAddr::Domain(_, _) => panic!("not a socket address"),
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        if let SocksAddr::Ip(addr) = self {
            Some(addr.ip())
        } else {
            None
        }
    }

    pub fn host(&self) -> String {
        match self {
            SocksAddr::Ip(ip) => ip.ip().to_string(),
            SocksAddr::Domain(domain, _) => domain.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            SocksAddr::Ip(ip) => ip.port(),
            SocksAddr::Domain(_, port) => *port,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            // SOCKS5 ATYP
            SocksAddr::Ip(ip) => match ip {
                SocketAddr::V4(_) => 1 + 4 + 2, // ATYP + IPv4 len + port len
                SocketAddr::V6(_) => 1 + 16 + 2,
            },
            SocksAddr::Domain(domain, _) => 1 + 1 + domain.len() + 2,
        }
    }

    pub fn peek_read(buf: &[u8]) -> io::Result<Self> {
        let mut cur = io::Cursor::new(buf);
        Self::peek_cursor(&mut cur)
    }

    #[inline]
    fn peek_cursor<T: AsRef<[u8]>>(cur: &mut io::Cursor<T>) -> io::Result<Self> {
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
                Ok(Self::Ip((addr, port).into()))
            }
            SocksAddrType::V6 => {
                if cur.remaining() < 16 + 2 {
                    return Err(io::Error::new(io::ErrorKind::Other, "invalid buf"));
                }
                let addr = Ipv6Addr::from(cur.get_u128());
                let port = cur.get_u16();
                Ok(Self::Ip((addr, port).into()))
            }
            SocksAddrType::DOMAIN => {
                let domain_len = cur.get_u8() as usize;
                if cur.remaining() < domain_len {
                    return Err(io::Error::new(io::ErrorKind::Other, "invalid buf"));
                }
                let mut buf = vec![0u8; domain_len];
                cur.copy_to_slice(&mut buf);
                let port = cur.get_u16();
                let domain_name = String::from_utf8(buf).map_err(|_x| invalid_domain())?;
                Ok(Self::Domain(domain_name, port))
            }
            _ => Err(invalid_atyp()),
        }
    }

    pub async fn read_from<T: AsyncRead + Unpin>(r: &mut T) -> io::Result<Self> {
        match r.read_u8().await? {
            SocksAddrType::V4 => {
                let ip = Ipv4Addr::from(r.read_u32().await?);
                let port = r.read_u16().await?;
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::V6 => {
                let ip = Ipv6Addr::from(r.read_u128().await?);
                let port = r.read_u16().await?;
                Ok(Self::Ip((ip, port).into()))
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
}

impl Clone for SocksAddr {
    fn clone(&self) -> Self {
        match self {
            SocksAddr::Ip(a) => Self::from(a.to_owned()),
            SocksAddr::Domain(domain, port) => Self::try_from((domain.clone(), *port)).unwrap(),
        }
    }
}

impl From<(IpAddr, u16)> for SocksAddr {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for SocksAddr {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for SocksAddr {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl TryFrom<(String, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from(value: (String, u16)) -> Result<Self, Self::Error> {
        if let Ok(ip) = value.0.parse::<IpAddr>() {
            return Ok(Self::from((ip, value.1)));
        }
        if value.0.len() > 0xff {
            return Err(io::Error::new(io::ErrorKind::Other, "domain too long"));
        }
        Ok(Self::Domain(value.0, value.1))
    }
}

impl TryFrom<&[u8]> for SocksAddr {
    type Error = io::Error;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
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
                Ok(Self::Ip((ip, port).into()))
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
                Ok(Self::Ip((ip, port).into()))
            }

            SocksAddrType::DOMAIN => {
                if buf.is_empty() {
                    return Err(insuff_bytes());
                }
                let domain_len = buf[1] as usize;
                if buf.len() < 1 + domain_len + 2 {
                    return Err(insuff_bytes());
                }
                let domain = String::from_utf8((buf[2..domain_len + 2]).to_vec()).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("invalid domain: {}", e))
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

impl TryFrom<SocksAddr> for SocketAddr {
    type Error = io::Error;

    fn try_from(s: SocksAddr) -> Result<Self, Self::Error> {
        match s {
            SocksAddr::Ip(ip) => Ok(ip),
            SocksAddr::Domain(_, _) => Err(io::Error::new(io::ErrorKind::Other, "cannot convert")),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Type {
    Http,
    HttpConnect,
    Socks5,
    Tun,

    Ignore,
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Network::Tcp => "TCP",
            Network::Udp => "UDP",
        })
    }
}

#[derive(Serialize)]
pub struct Session {
    /// The network type, representing either TCP or UDP.
    pub network: Network,
    /// The type of the inbound connection.
    pub typ: Type,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: SocksAddr,
    /// The packet mark SO_MARK
    pub packet_mark: Option<u32>,
    /// The bind interface
    pub iface: Option<Interface>,
}

impl Session {
    pub fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send + Sync>> {
        let mut rv = HashMap::new();
        rv.insert("network".to_string(), Box::new(self.network) as _);
        rv.insert("type".to_string(), Box::new(self.typ) as _);
        rv.insert("sourceIP".to_string(), Box::new(self.source.ip()) as _);
        rv.insert("sourcePort".to_string(), Box::new(self.source.port()) as _);
        rv.insert(
            "destinationIP".to_string(),
            Box::new(self.destination.ip()) as _,
        );
        rv.insert(
            "destinationPort".to_string(),
            Box::new(self.destination.port()) as _,
        );
        rv.insert("host".to_string(), Box::new(self.destination.host()) as _);

        rv
    }
}

impl Default for Session {
    fn default() -> Self {
        Self {
            network: Network::Tcp,
            typ: Type::Http,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            destination: SocksAddr::any_ipv4(),
            packet_mark: None,
            iface: None,
        }
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} -> {}",
            self.network, self.source, self.destination,
        )
    }
}

impl Debug for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("network", &self.network)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("packet_mark", &self.packet_mark)
            .field("iface", &self.iface)
            .finish()
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            network: self.network,
            typ: self.typ,
            source: self.source,
            destination: self.destination.clone(),
            packet_mark: self.packet_mark,
            iface: self.iface.as_ref().cloned(),
        }
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
