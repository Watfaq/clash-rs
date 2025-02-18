#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::add_route;
#[cfg(windows)]
pub use windows::maybe_routes_clean_up;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::add_route;
#[cfg(target_os = "macos")]
pub use macos::maybe_routes_clean_up;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::add_route;
#[cfg(target_os = "linux")]
pub use linux::maybe_routes_clean_up;

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod other;
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
use other::add_route;
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub use other::maybe_routes_clean_up;

use tracing::warn;

use crate::{
    app::net::OutboundInterface, common::errors::map_io_error,
    config::internal::config::TunConfig,
};

use network_interface::NetworkInterfaceConfig;

pub fn maybe_add_routes(cfg: &TunConfig, tun_name: &str) -> std::io::Result<()> {
    if cfg.route_all || !cfg.routes.is_empty() {
        #[cfg(target_os = "linux")]
        linux::check_ip_command_installed()?;

        let tun_iface = network_interface::NetworkInterface::show()
            .map_err(map_io_error)?
            .into_iter()
            .find(|iface| iface.name == tun_name)
            .map(|x| OutboundInterface {
                name: x.name,
                addr_v4: x.addr.iter().find_map(|addr| match addr {
                    network_interface::Addr::V4(addr) => Some(addr.ip),
                    _ => None,
                }),
                addr_v6: x.addr.iter().find_map(|addr| match addr {
                    network_interface::Addr::V6(addr) => Some(addr.ip),
                    _ => None,
                }),
                index: x.index,
            })
            .expect("tun interface not found");

        if cfg.route_all {
            warn!(
                "route_all is enabled, all traffic will be routed through the tun \
                 interface"
            );

            #[cfg(not(target_os = "linux"))]
            {
                use ipnet::IpNet;

                use std::net::Ipv4Addr;

                let default_routes = vec![
                    IpNet::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1)
                        .unwrap(),
                    IpNet::new(std::net::IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
                        .unwrap(),
                ];
                for r in default_routes {
                    add_route(&tun_iface, &r)?;
                }

                #[cfg(target_os = "macos")]
                {
                    macos::maybe_add_default_route()?;
                }
            }
            #[cfg(target_os = "linux")]
            {
                linux::setup_policy_routing(cfg, &tun_iface)?;

                // support additional routes on linux when route_all is enabled
                for r in &cfg.routes {
                    add_route(&tun_iface, r)?;
                }
            }
        } else {
            for r in &cfg.routes {
                add_route(&tun_iface, r)?;
            }
        }
    }

    Ok(())
}
