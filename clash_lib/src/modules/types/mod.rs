mod interface;
mod target_addr;
mod udp_packet;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

pub use interface::*;
pub use target_addr::*;
pub use udp_packet::*;

use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
pub struct DualIpAddr {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

impl From<IpAddr> for DualIpAddr {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(addr) => DualIpAddr {
                v4: Some(addr),
                v6: None,
            },
            IpAddr::V6(addr) => DualIpAddr {
                v4: None,
                v6: Some(addr),
            },
        }
    }
}

impl From<(Option<Ipv4Addr>, Option<Ipv6Addr>)> for DualIpAddr {
    fn from(value: (Option<Ipv4Addr>, Option<Ipv6Addr>)) -> Self {
        Self {
            v4: value.0,
            v6: value.1,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TargetStack(pub bool, pub bool);

impl From<(bool, bool)> for TargetStack {
    fn from(value: (bool, bool)) -> Self {
        TargetStack(value.0, value.1)
    }
}

impl From<&(Option<Ipv4Addr>, Option<Ipv6Addr>)> for TargetStack {
    fn from(value: &(Option<Ipv4Addr>, Option<Ipv6Addr>)) -> Self {
        (value.0.is_some(), value.1.is_some()).into()
    }
}

impl From<&SocketAddr> for TargetStack {
    fn from(value: &SocketAddr) -> Self {
        match value {
            SocketAddr::V4(_) => Self(true, false),
            SocketAddr::V6(_) => Self(false, true),
        }
    }
}
impl From<&IpAddr> for TargetStack {
    fn from(value: &IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self(true, false),
            IpAddr::V6(_) => Self(false, true),
        }
    }
}

impl From<&DualIpAddr> for TargetStack {
    fn from(value: &DualIpAddr) -> Self {
        Self(value.v4.is_some(), value.v6.is_some())
    }
}
