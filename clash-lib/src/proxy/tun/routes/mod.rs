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

use crate::config::internal::config::TunConfig;

use crate::app::net::get_interface_by_name;

#[allow(dead_code)]
pub fn maybe_add_routes(cfg: &TunConfig, tun_name: &str) -> std::io::Result<()> {
    if cfg.route_all || !cfg.routes.is_empty() {
        #[cfg(target_os = "linux")]
        linux::check_ip_command_installed()?;

        let tun_iface =
            get_interface_by_name(tun_name).expect("tun interface not found");

        if cfg.route_all {
            warn!(
                "route_all is enabled, all traffic will be routed through the tun \
                 interface"
            );

            #[cfg(not(target_os = "linux"))]
            {
                use ipnet::IpNet;

                use std::net::Ipv4Addr;

                let mut default_routes = vec![
                    IpNet::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1)
                        .unwrap(),
                    IpNet::new(std::net::IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
                        .unwrap(),
                ];

                if tun_iface.addr_v6.is_some() {
                    // Add default IPv6 route
                    default_routes.append(&mut vec![
                        IpNet::new(
                            std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                                0, 0, 0, 0, 0, 0, 0, 0,
                            )),
                            1,
                        )
                        .unwrap(),
                        IpNet::new(
                            std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                                0x8000, 0, 0, 0, 0, 0, 0, 0,
                            )),
                            1,
                        )
                        .unwrap(),
                    ]);
                }

                for r in default_routes {
                    add_route(&tun_iface, &r)?;
                }

                #[cfg(target_os = "windows")]
                {
                    // Set DNS server or DNS hijack won't work
                    // We can't set name server to clash DNS listener address
                    // because it may not be on standard port 53
                    // Windows only support DNS server on port 53
                    if cfg.dns_hijack {
                        warn!(
                            "DNS hijack is enabled, setting fake DNS servers for \
                             the tun interface"
                        );
                        let name_server = vec!["1.1.1.1".parse().unwrap()];
                        let _ = windows::set_dns_v4(&tun_iface, &name_server)
                            .map_err(|e| {
                                tracing::error!("failed to set dns due to:{}", e)
                            });
                        let name_server_v6 =
                            vec!["2606:4700:4700::1111".parse().unwrap()];
                        let _ = windows::set_dns_v6(&tun_iface, &name_server_v6)
                            .map_err(|e| {
                                tracing::error!("failed to set dns due to:{}", e)
                            });
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    macos::maybe_add_default_route()?;
                }
            }
            #[cfg(target_os = "linux")]
            {
                linux::setup_policy_routing(cfg, &tun_iface)?;
            }
        } else {
            for r in &cfg.routes {
                add_route(&tun_iface, r)?;
            }
        }
    }

    Ok(())
}
