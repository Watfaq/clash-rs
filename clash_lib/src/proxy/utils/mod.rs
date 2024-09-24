use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

#[cfg(all(test, docker_test))]
pub mod test_utils;

mod platform;

pub mod provider_helper;
mod proxy_connector;
mod socket_helpers;

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
pub use proxy_connector::*;

use serde::{Deserialize, Serialize};
pub use socket_helpers::*;
use tracing::{debug, trace};

#[derive(Debug)]
pub struct OutboundInterface {
    pub name: String,
    #[allow(unused)]
    pub addr_v4: Option<Ipv4Addr>,
    #[allow(unused)]
    pub addr_v6: Option<Ipv6Addr>,
    #[allow(unused)]
    pub index: u32,
}

pub fn get_outbound_interface() -> Option<OutboundInterface> {
    fn get_outbound_ip_from_interface(
        iface: &NetworkInterface,
    ) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        let mut v4 = None;
        let mut v6 = None;

        for addr in iface.addr.iter() {
            trace!("inspect interface address: {:?} on {}", addr, iface.name);

            if v4.is_some() && v6.is_some() {
                break;
            }

            match addr {
                network_interface::Addr::V4(addr) => {
                    if !addr.ip.is_loopback()
                        && !addr.ip.is_link_local()
                        && !addr.ip.is_unspecified()
                    {
                        v4 = Some(addr.ip);
                    }
                }
                network_interface::Addr::V6(addr) => {
                    if addr.ip.is_global() && !addr.ip.is_unspecified() {
                        v6 = Some(addr.ip);
                    }
                }
            }
        }

        (v4, v6)
    }

    let now = std::time::Instant::now();

    let mut all_outbounds = network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .filter(|iface| {
            !iface.name.contains("tun") && {
                let found = get_outbound_ip_from_interface(iface);
                found.0.is_some() || found.1.is_some()
            }
        })
        .map(|x| {
            let addr = get_outbound_ip_from_interface(&x);
            OutboundInterface {
                name: x.name,
                addr_v4: addr.0,
                addr_v6: addr.1,
                index: x.index,
            }
        })
        .collect::<Vec<_>>();

    let priority = ["eth", "en", "pdp_ip"];

    all_outbounds.sort_by(|left, right| {
        let left = priority
            .iter()
            .position(|x| left.name.contains(x))
            .unwrap_or(usize::MAX);
        let right = priority
            .iter()
            .position(|x| right.name.contains(x))
            .unwrap_or(usize::MAX);

        left.cmp(&right)
    });

    debug!(
        "sorted outbound interfaces: {:?}, took: {}ms",
        all_outbounds,
        now.elapsed().as_millis()
    );

    all_outbounds.into_iter().next()
}

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
            _ => None,
        }
    }

    pub fn into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            Interface::IpAddr(ip) => Some(SocketAddr::new(ip, 0)),
            _ => None,
        }
    }

    pub fn into_iface_name(self) -> Option<String> {
        match self {
            Interface::IpAddr(_) => None,
            Interface::Name(name) => Some(name),
        }
    }
}
