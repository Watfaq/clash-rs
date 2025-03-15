use serde::Serialize;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum TargetAddr {
    Socket(SocketAddr),
    Domain(String, u16),
}

impl TryFrom<(String, u16)> for TargetAddr {
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

impl FromStr for TargetAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_string();
        if !s.contains(':') {
            return Err(anyhow!("missing port"));
        }
        match SocketAddr::from_str(&s) {
            Ok(v) => Ok(Self::Socket(v)),
            Err(_) => {
                let tokens: Vec<_> = s.split(':').collect();
                if tokens.len() == 2 {
                    let port: u16 = tokens.get(1).unwrap().parse()?;
                    Ok(Self::Domain(tokens.first().unwrap().to_string(), port))
                } else {
                    Err(anyhow!("SocksAddr parse error, value: {s}"))
                }
            }
        }
    }
}
impl Display for TargetAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            TargetAddr::Socket(addr) => write!(f, "{}", addr),
            TargetAddr::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

impl Default for TargetAddr {
    fn default() -> Self {
        Self::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
    }
}

impl TargetAddr {
    pub fn any_ipv4() -> Self {
        Self::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
    }

    pub fn any_ipv6() -> Self {
        Self::Socket(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            0,
        ))
    }

    pub fn is_domain(&self) -> bool {
        match self {
            TargetAddr::Socket(_) => false,
            TargetAddr::Domain(..) => true,
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            TargetAddr::Socket(_) => None,
            TargetAddr::Domain(domain, _) => Some(domain.as_str()),
        }
    }

    pub fn must_into_socket_addr(self) -> SocketAddr {
        match self {
            TargetAddr::Socket(addr) => addr,
            TargetAddr::Domain(..) => panic!("not a socket address"),
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        if let TargetAddr::Socket(addr) = self {
            Some(addr.ip())
        } else {
            None
        }
    }

    pub fn host(&self) -> String {
        match self {
            TargetAddr::Socket(ip) => ip.ip().to_string(),
            TargetAddr::Domain(domain, _) => domain.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Socket(ip) => ip.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }

}

impl Clone for TargetAddr {
    fn clone(&self) -> Self {
        match self {
            TargetAddr::Socket(a) => Self::from(a.to_owned()),
            TargetAddr::Domain(domain, port) => {
                Self::try_from((domain.clone(), *port)).unwrap()
            }
        }
    }
}

impl From<(IpAddr, u16)> for TargetAddr {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Socket(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for TargetAddr {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Socket(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for TargetAddr {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Socket(value.into())
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Socket(value)
    }
}

impl TryFrom<TargetAddr> for SocketAddr {
    type Error = anyhow::Error;

    fn try_from(s: TargetAddr) -> Result<Self, Self::Error> {
        match s {
            TargetAddr::Socket(ip) => Ok(ip),
            TargetAddr::Domain(..) => {
                Err(anyhow!("cannot convert domain into SocketAddress"))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::{net::SocketAddr, str::FromStr as _};

    use crate::session::TargetAddr;

    #[test]
    fn test_from_str() {
        assert_eq!(
            TargetAddr::from_str("127.0.0.1:80").unwrap(),
            TargetAddr::Socket(SocketAddr::V4("127.0.0.1:80".parse().unwrap()))
        );
        assert!(TargetAddr::from_str("127.0.0.1:80").is_ok());
        assert!(TargetAddr::from_str("hosta.com:443").is_ok());
        assert!(TargetAddr::from_str("hosta.:com:443").is_err());
    }
}
