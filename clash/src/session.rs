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

impl From<SocketAddr> for SocksAddr {
    fn from(val: SocketAddr) -> Self {
        Self::Ip(val)
    }
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
    /// The tag of the inbound handler this session initiated.
    pub inbound_tag: String,
    /// The tag of the first outbound handler this session goes.
    pub outbound_tag: String,
    /// Optional stream ID for multiplexing transports.
    pub stream_id: Option<StreamId>,
    /// Optional source address which is forwarded via HTTP reverse proxy.
    pub forwarded_source: Option<IpAddr>,
    /// Instructs a multiplexed transport should creates a new underlying
    /// connection for this session, and it will be used only once.
    pub new_conn_once: bool,
}

fn invalid_domain() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "invalid domain")
}

fn invalid_atyp() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "invalid address type")
}
