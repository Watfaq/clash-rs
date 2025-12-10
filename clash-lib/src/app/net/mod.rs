use network_interface::{
    NetworkInterface, NetworkInterfaceConfig, V4IfAddr, V6IfAddr,
};
use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, LazyLock},
};

use serde::{Deserialize, Serialize};
use tracing::trace;

pub static DEFAULT_OUTBOUND_INTERFACE: LazyLock<
    Arc<tokio::sync::RwLock<Option<OutboundInterface>>>,
> = LazyLock::new(Default::default);
pub static TUN_SOMARK: LazyLock<tokio::sync::RwLock<Option<u32>>> =
    LazyLock::new(Default::default);

/// Initialize network configuration
/// globally manage default outbound interface
/// This function should be called as early as possible
/// so that other config initialization can use the default outbound interface
pub async fn init_net_config(tun_somark: u32) {
    *DEFAULT_OUTBOUND_INTERFACE.write().await = get_outbound_interface();
    *TUN_SOMARK.write().await = Some(tun_somark);

    trace!(
        "default outbound interface: {:?}, tun somark: {:?}",
        *DEFAULT_OUTBOUND_INTERFACE.read().await,
        *TUN_SOMARK.read().await
    );
}

/// Represents a parsed outbound interface for use in runtime.
#[derive(Serialize, Debug, Clone)]
pub struct OutboundInterface {
    pub name: String,
    pub addr_v4: Option<Ipv4Addr>,
    pub netmask_v4: Option<Ipv4Addr>,
    pub broadcast_v4: Option<Ipv4Addr>,
    pub addr_v6: Option<Ipv6Addr>,
    pub netmask_v6: Option<Ipv6Addr>,
    pub broadcast_v6: Option<Ipv6Addr>,
    pub index: u32,
    pub mac_addr: Option<String>,
}

impl From<NetworkInterface> for OutboundInterface {
    fn from(iface: NetworkInterface) -> Self {
        fn get_outbound_ip_from_interface(
            iface: &NetworkInterface,
        ) -> (Option<V4IfAddr>, Option<V6IfAddr>) {
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
                            v4 = Some(*addr);
                        }
                    }
                    network_interface::Addr::V6(addr) => {
                        if addr.ip.is_unique_local() || addr.ip.is_global() {
                            v6 = Some(*addr);
                        }
                    }
                }
            }

            (v4, v6)
        }

        let addr = get_outbound_ip_from_interface(&iface);
        OutboundInterface {
            name: iface.name,
            addr_v4: addr.0.map(|x| x.ip),
            netmask_v4: addr.0.and_then(|x| x.netmask),
            broadcast_v4: addr.0.and_then(|x| x.broadcast),
            addr_v6: addr.1.map(|x| x.ip),
            netmask_v6: addr.1.and_then(|x| x.netmask),
            broadcast_v6: addr.1.and_then(|x| x.broadcast),
            index: iface.index,
            mac_addr: iface.mac_addr,
        }
    }
}
impl std::fmt::Display for OutboundInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (v4: {}, v6: {}, index: {}, mac: {})",
            self.name,
            self.addr_v4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.addr_v6
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "None".to_string()),
            self.index,
            self.mac_addr.clone().unwrap_or_else(|| "None".to_string())
        )
    }
}

pub fn get_interface_by_name(name: &str) -> Option<OutboundInterface> {
    let now = std::time::Instant::now();

    let outbound = network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .find(|iface| iface.name == name)?
        .into();

    trace!(
        "found interface by name: {:?}, took: {}ms",
        outbound,
        now.elapsed().as_millis()
    );

    Some(outbound)
}

pub fn get_outbound_interface() -> Option<OutboundInterface> {
    let now = std::time::Instant::now();

    let mut all_outbounds = network_interface::NetworkInterface::show()
        .ok()?
        .into_iter()
        .map(Into::into)
        .filter(|iface: &OutboundInterface| {
            !iface.name.contains("tun")
                && (iface.addr_v4.is_some() || iface.addr_v6.is_some())
        })
        .collect::<Vec<_>>();

    // Interface name priority (wired > wireless > cellular > vpn)
    // Lower index = higher priority
    let priority = [
        "eth",       // 0 - Linux/Android wired (eth0, eth1)
        "Ethernet",  // 1 - Windows wired
        "en",        // 2 - macOS/iOS network interface (en0, en1)
        "WLAN",      // 3 - Windows/Android wireless (wlan0)
        "Wi-Fi",     // 4 - Windows/macOS wireless
        "wlp",       // 5 - Linux wireless (wlp2s0)
        "pdp_ip",    // 6 - iOS cellular (expensive, prefer WiFi)
        "rmnet",     // 7 - Android cellular Qualcomm (rmnet_data0, rmnet0)
        "ccmni",     // 8 - Android cellular MTK (ccmni0)
        "vEthernet", // 9 - Windows virtual (Hyper-V)
        "Tailscale", // 10 - VPN (lowest priority to avoid routing loops)
    ];

    all_outbounds.sort_by(|left, right| {
        // Priority 1: Interface name priority (highest priority)
        let left_pri = priority
            .iter()
            .position(|x| left.name.contains(x))
            .unwrap_or(usize::MAX);
        let right_pri = priority
            .iter()
            .position(|x| right.name.contains(x))
            .unwrap_or(usize::MAX);

        match left_pri.cmp(&right_pri) {
            std::cmp::Ordering::Equal => {
                // Priority 2: IPv6 existence (when interface priority is same)
                match (left.addr_v6, right.addr_v6) {
                    (Some(_), None) => return std::cmp::Ordering::Less,
                    (None, Some(_)) => return std::cmp::Ordering::Greater,
                    (Some(left_v6), Some(right_v6)) => {
                        // Priority 3: IPv6 global unicast priority
                        if left_v6.is_unicast_global() && !right_v6.is_unicast_global() {
                            return std::cmp::Ordering::Less;
                        } else if !left_v6.is_unicast_global() && right_v6.is_unicast_global() {
                            return std::cmp::Ordering::Greater;
                        }
                    }
                    _ => {}
                }
                // Priority 4: Alphabetical order
                left.name.cmp(&right.name)
            }
            other => other,
        }
    });

    trace!(
        "sorted outbound interfaces: {:?}, took: {}ms",
        all_outbounds,
        now.elapsed().as_millis()
    );

    all_outbounds.into_iter().next()
}

/// Represents a network interface in configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Interface {
    IpAddr(IpAddr),
    Name(String),
}

impl From<&str> for Interface {
    fn from(s: &str) -> Self {
        Self::Name(s.to_owned())
    }
}

impl From<IpAddr> for Interface {
    fn from(ip: IpAddr) -> Self {
        Self::IpAddr(ip)
    }
}

impl Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Interface::IpAddr(ip) => write!(f, "{ip}"),
            Interface::Name(name) => write!(f, "{name}"),
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
