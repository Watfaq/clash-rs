use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

pub type StreamId = u64;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct DatagramSource {
    pub address: SocketAddr,
    pub stream_id: Option<StreamId>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

struct SocksAddrType;

impl SocksAddrType {
    const V4: u8 = 0x1;
    const DOMAIN: u8 = 0x3;
    const V6: u8 = 0x4;
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

    pub fn ip(&self) -> Option<IpAddr> {
        if let SocksAddr::Ip(addr) = self {
            Some(addr.ip())
        } else {
            None
        }
    }

    pub fn host(&self) -> &str {
        match self {
            SocksAddr::Ip(ip) => ip.ip().to_string().as_str(),
            SocksAddr::Domain(domain, _) => domain,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            SocksAddr::Ip(ip) => ip.port(),
            SocksAddr::Domain(_, port) => port.clone(),
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
            SocksAddr::Domain(domain, port) => Self::try_from((domain, port)).unwrap(),
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
                let ip = Ipv4Addr::from(ip_bytes);
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
                let domain =
                    String::from_utf8((&buf[2..domain_len + 2]).to_vec()).map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, format!("invalid domain: {}", e))
                    })?;
                let mut port_bytes = [0u8; 2];
                (&mut port_bytes).copy_from_slice(&buf[domain_len + 2..domain_len + 4]);
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

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum Network {
    Tcp,
    Udp,
}

pub struct Session {
    /// The network type, representing either TCP or UDP.
    pub network: Network,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The socket address of the local socket of an inbound connection.
    pub local_addr: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: SocksAddr,
    /// The outbound target
    pub outbound_target: String,
    /// The packet mark SO_MARK
    pub packet_mark: Option<u32>,
    /// The bind interface
    pub iface: Option<SocketAddr>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            network: Network::Tcp,
            source: SocksAddr::any_ipv4(),
            local_addr: SocksAddr::any_ipv4(),
            destination: SocksAddr::any_ipv4(),
            outbound_target: "".to_string(),
            packet_mark: None,
            iface: None,
        }
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            network: self.network,
            source: self.source,
            local_addr: self.local_addr,
            destination: self.destination.clone(),
            outbound_target: self.outbound_target.clone(),
            packet_mark: self.packet_mark,
            iface: self.iface,
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
