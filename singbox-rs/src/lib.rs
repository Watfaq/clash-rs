use std::{
    fmt::{Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};

mod common;
mod io;
mod utils;
pub mod vmess;

pub trait ProxyStream:
    AsyncRead + AsyncWrite + Send + Sync + Unpin + std::fmt::Debug
{
}
impl<T> ProxyStream for T where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + std::fmt::Debug
{
}
pub type AnyStream = Box<dyn ProxyStream>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid url: {0}")]
    InvalidUrl(String),
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub enum SocksAddr {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

impl SocksAddr {
    pub fn any_ipv4() -> Self {
        Self::default()
    }

    pub fn any_ipv6() -> Self {
        Self::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 0)
    }
}

impl FromStr for SocksAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.to_string();
        if !s.contains(':') {
            s = format!("{s}:80");
        }
        match SocketAddr::from_str(&s) {
            Ok(v) => Ok(Self::Ip(v.ip(), v.port())),
            Err(_) => {
                let tokens: Vec<_> = s.split(':').collect();
                if tokens.len() == 2 {
                    let port: u16 = tokens
                        .get(1)
                        .unwrap()
                        .parse()
                        .map_err(|_| Error::InvalidUrl(s.clone()))?;
                    Ok(Self::Domain(tokens.first().unwrap().to_string(), port))
                } else {
                    Err(Error::InvalidUrl(s))
                }
            }
        }
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value.ip(), value.port())
    }
}

impl Default for SocksAddr {
    fn default() -> Self {
        Self::Ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
    }
}

impl Display for SocksAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SocksAddr::Ip(ip, port) => format!("{}:{}", ip, port),
                SocksAddr::Domain(host, port) => format!("{}:{}", host, port),
            }
        )
    }
}

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    pub dst_addr: SocksAddr,
}

impl Default for UdpPacket {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::any_ipv4(),
        }
    }
}

impl std::fmt::Debug for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .finish()
    }
}

impl std::fmt::Display for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP Packet from {} to {} with {} bytes",
            self.src_addr,
            self.dst_addr,
            self.data.len()
        )
    }
}

impl UdpPacket {
    pub fn new(data: Vec<u8>, src_addr: SocksAddr, dst_addr: SocksAddr) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
        }
    }
}
