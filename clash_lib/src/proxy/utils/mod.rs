use std::net::{IpAddr, SocketAddr};

pub mod provider_helper;
mod socket_helpers;

pub use socket_helpers::*;

#[derive(Debug, Clone)]
pub enum Interface {
    IpAddr(IpAddr),
    Name(String),
}

impl Interface {
    pub fn into_ip_addr(self) -> Option<IpAddr> {
        match self {
            Interface::IpAddr(ip) => Some(ip),
            Interface::Name(_) => None,
        }
    }

    pub fn into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            Interface::IpAddr(ip) => Some(SocketAddr::new(ip, 0)),
            Interface::Name(_) => None,
        }
    }

    pub fn into_iface_name(self) -> Option<String> {
        match self {
            Interface::IpAddr(_) => None,
            Interface::Name(iface) => Some(iface),
        }
    }
}
