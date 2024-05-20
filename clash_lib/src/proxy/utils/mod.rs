use std::{
    fmt::Display,
    net::{IpAddr, SocketAddr},
};

#[cfg(all(test, not(ci)))]
pub mod test_utils;

pub mod provider_helper;
mod proxy_connector;
mod socket_helpers;

pub use proxy_connector::*;

use serde::{Deserialize, Serialize};
pub use socket_helpers::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Interface {
    IpAddr(IpAddr),
    Name(String),
}

impl Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Interface::IpAddr(ip) => write!(f, "{}", ip),
            Interface::Name(name) => write!(f, "{}", name),
        }
    }
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
