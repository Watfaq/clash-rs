use std::{
    fmt,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    vec,
};

use shadowquic_macros::{SDecode, SEncode};

use super::{SDecode, SEncode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[rustfmt::skip]
pub mod consts {
    pub const SOCKS5_VERSION:                          u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE:                 u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_GSSAPI:               u8 = 0x01;
    pub const SOCKS5_AUTH_METHOD_PASSWORD:             u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE:       u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT:                  u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND:                     u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE:                u8 = 0x03;

    pub const SOCKS5_ADDR_TYPE_IPV4:                   u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME:            u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6:                   u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED:                  u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE:            u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:     u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE:        u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE:           u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED:         u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED:                u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:      u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
    pub const SOCKS5_RESERVE:                          u8 = 0x00;                 
}

pub use consts::*;

use crate::error::SError;

#[derive(Clone, Debug, SDecode, SEncode)]
pub struct AuthReq {
    pub version: u8,
    pub methods: VarVec,
}

#[derive(Clone, Debug, SDecode, SEncode)]
pub struct PasswordAuthReq {
    pub version: u8,
    pub username: VarVec,
    pub password: VarVec,
}

#[derive(Clone, Debug, SDecode, SEncode)]
pub struct PasswordAuthReply {
    pub version: u8,
    pub status: u8,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct VarVec {
    pub len: u8,
    pub contents: Vec<u8>,
}

impl From<Vec<u8>> for VarVec {
    fn from(vec: Vec<u8>) -> Self {
        VarVec {
            len: vec.len() as u8,
            contents: vec,
        }
    }
}

#[async_trait::async_trait]
impl SEncode for VarVec {
    async fn encode<T: AsyncWrite + Unpin + Send>(&self, s: &mut T) -> Result<(), SError> {
        let buf = vec![self.len];
        s.write_all(&buf).await?;
        s.write_all(&self.contents[0..self.len as usize]).await?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl SDecode for VarVec {
    async fn decode<T: AsyncRead + Unpin + Send>(s: &mut T) -> Result<Self, SError> {
        let mut buf = [0u8; 1];
        s.read_exact(&mut buf).await?;
        let mut buf2 = vec![0u8; buf[0] as usize];
        s.read_exact(&mut buf2).await?;
        Ok(Self {
            len: buf[0],
            contents: buf2,
        })
    }
}

#[derive(Clone, Debug, SDecode, SEncode)]
pub struct AuthReply {
    pub version: u8,
    pub method: u8,
}

#[derive(Clone, Debug, SDecode, SEncode)]
pub struct CmdReq {
    pub version: u8,
    pub cmd: u8,
    pub rsv: u8,
    pub dst: SocksAddr,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, SDecode, SEncode)]
pub struct SocksAddr {
    pub addr: AddrOrDomain,
    pub port: u16,
}
impl SocksAddr {
    pub fn from_domain(name: String, port: u16) -> Self {
        SocksAddr {
            addr: AddrOrDomain::Domain(VarVec {
                len: name.len() as u8,
                contents: name.into_bytes(),
            }),
            port,
        }
    }
}
impl fmt::Display for SocksAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let AddrOrDomain::V6(_) = self.addr {
            write!(f, "[{}]:{}", self.addr, self.port)
        } else {
            write!(f, "{}:{}", self.addr, self.port)
        }
    }
}
#[derive(Clone, Debug, Hash, PartialEq, Eq, SDecode, SEncode)]
#[repr(u8)]
pub enum AddrOrDomain {
    V4([u8; 4]) = SOCKS5_ADDR_TYPE_IPV4,
    V6([u8; 16]) = SOCKS5_ADDR_TYPE_IPV6,
    Domain(VarVec) = SOCKS5_ADDR_TYPE_DOMAIN_NAME,
}
impl fmt::Display for AddrOrDomain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            AddrOrDomain::V4(x) => write!(f, "{}", IpAddr::from(*x))?,
            AddrOrDomain::V6(x) => write!(f, "{}", IpAddr::from(*x))?,
            AddrOrDomain::Domain(var_vec) => write!(
                f,
                "{}",
                String::from_utf8(var_vec.contents.clone()).map_err(|_| fmt::Error)?
            )?,
        }
        Ok(())
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(socket_addr_v4) => SocksAddr {
                addr: AddrOrDomain::V4(socket_addr_v4.ip().octets()),
                port: socket_addr_v4.port(),
            },
            SocketAddr::V6(socket_addr_v6) => SocksAddr {
                addr: AddrOrDomain::V6(socket_addr_v6.ip().octets()),
                port: socket_addr_v6.port(),
            },
        }
    }
}
impl ToSocketAddrs for SocksAddr {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<vec::IntoIter<SocketAddr>> {
        match &self.addr {
            AddrOrDomain::Domain(x) => (
                std::str::from_utf8(&x.contents).expect("Domain Name is not UTF8"),
                self.port,
            )
                .to_socket_addrs(),
            AddrOrDomain::V4(x) => {
                Ok(vec![SocketAddr::from((x.to_owned(), self.port))].into_iter())
            }
            AddrOrDomain::V6(x) => {
                Ok(vec![SocketAddr::from((x.to_owned(), self.port))].into_iter())
            }
        }
    }
}

#[derive(Clone, Debug, SEncode, SDecode)]
pub struct CmdReply {
    pub version: u8,
    pub rep: u8,
    pub rsv: u8,
    pub bind_addr: SocksAddr,
}

#[derive(SEncode, SDecode)]
pub struct UdpReqHeader {
    pub rsv: u16,
    pub frag: u8,
    pub dst: SocksAddr,
}

macro_rules! gen_num_type_sencode {
    ($($t:ty),*) => {
        $(
            #[async_trait::async_trait]
            impl SEncode for $t {
                async fn encode<T: AsyncWrite + Unpin + Send>(&self, s: &mut T) -> Result<(), SError> {
                    s.write_all(&self.to_be_bytes()).await?;
                    Ok(())
                }
            }
        )*
    };
}
gen_num_type_sencode!(u8, u16, u32, u64, u128, f64);

macro_rules! gen_num_type_sdecode {
    ($($t:ty),*) => {
        $(
            #[async_trait::async_trait]
            impl SDecode for $t {
                async fn decode<T: AsyncRead + Unpin + Send>(s: &mut T) -> Result<Self, SError> {
                    let mut buf = [0u8; std::mem::size_of::<$t>()];
                    s.read_exact(&mut buf).await?;
                    let val = <$t>::from_be_bytes(buf);
                    Ok(val)
                }
            }
        )*
    };
}

gen_num_type_sdecode!(u8, u16, u32, u64, u128, f64);
