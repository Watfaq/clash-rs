use std::net::Ipv4Addr;

use ipnet::IpNet;
use tracing::warn;

use crate::{
    app::net::{OutboundInterface, get_outbound_interface},
    common::errors::new_io_error,
    config::internal::config::TunConfig,
};

/// let's assume that the `route` command is available on macOS
pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let mut cmd = std::process::Command::new("route");
    cmd.arg("add");

    match dest {
        IpNet::V4(_) => {
            cmd.arg("-net")
                .arg(dest.to_string())
                .arg("-interface")
                .arg(&via.name);
            warn!("executing: route add -net {} -interface {}", dest, via.name);
        }
        IpNet::V6(_) => {
            cmd.arg("-inet6")
                .arg(dest.to_string())
                .arg("-interface")
                .arg(&via.name);
            warn!(
                "executing: route add -inet6 {} -interface {}",
                dest, via.name
            );
        }
    }

    let output = cmd.output()?;

    if !output.status.success() {
        Err(new_io_error("add route failed"))
    } else {
        Ok(())
    }
}

fn get_default_gateway()
-> std::io::Result<(Option<Ipv4Addr>, Option<std::net::Ipv6Addr>)> {
    // IPv4
    let cmd_v4 = std::process::Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("default")
        .output()?;

    let mut gateway_v4 = None;
    if cmd_v4.status.success() {
        let output = String::from_utf8_lossy(&cmd_v4.stdout);
        for line in output.lines() {
            if line.trim().contains("gateway:") {
                gateway_v4 = line
                    .split_whitespace()
                    .last()
                    .and_then(|x| x.parse::<Ipv4Addr>().ok());
                break;
            }
        }
    }

    // IPv6
    let cmd_v6 = std::process::Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("-inet6")
        .arg("default")
        .output()?;

    let mut gateway_v6 = None;
    if cmd_v6.status.success() {
        let output = String::from_utf8_lossy(&cmd_v6.stdout);
        for line in output.lines() {
            if line.trim().contains("gateway:") {
                gateway_v6 = line
                    .split_whitespace()
                    .last()
                    .and_then(|x| x.parse::<std::net::Ipv6Addr>().ok());
                break;
            }
        }
    }

    Ok((gateway_v4, gateway_v6))
}

/// it seems to be fine to add the default route multiple times
pub fn maybe_add_default_route() -> std::io::Result<()> {
    let (gateway_v4, gateway_v6) = get_default_gateway()?;
    let default_interface =
        get_outbound_interface().ok_or(new_io_error("get default interface"))?;

    // Add IPv4 default route if gateway found
    if let Some(gateway) = gateway_v4 {
        let cmd = std::process::Command::new("route")
            .arg("add")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("0/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route add -ifscope {} 0/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            return Err(new_io_error("add default route failed"));
        }
    }

    if let Some(gateway) = gateway_v6 {
        let cmd = std::process::Command::new("route")
            .arg("add")
            .arg("-inet6")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("::/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route add -inet6 -ifscope {} ::/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            return Err(new_io_error("add default IPv6 route failed"));
        }
    }

    if gateway_v4.is_none() {
        Err(new_io_error(
            "cant set default route, default gateway not found",
        ))
    } else {
        Ok(())
    }
}

/// failing to delete the default route won't cause route failure
pub fn maybe_routes_clean_up(_: &TunConfig) -> std::io::Result<()> {
    let (gateway_v4, gateway_v6) = get_default_gateway()?;
    let default_interface =
        get_outbound_interface().ok_or(new_io_error("get default interface"))?;

    let mut result = Ok(());

    // Clean up IPv4 default route
    if let Some(gateway) = gateway_v4 {
        let cmd = std::process::Command::new("route")
            .arg("delete")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("0/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route delete -ifscope {} 0/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            result = Err(new_io_error("delete default IPv4 route failed"));
        }
    }

    // Clean up IPv6 default route
    if let Some(gateway) = gateway_v6 {
        let cmd = std::process::Command::new("route")
            .arg("delete")
            .arg("-inet6")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("::/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route delete -inet6 -ifscope {} ::/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            result = Err(new_io_error("delete default IPv6 route failed"));
        }
    }

    if gateway_v4.is_none() && gateway_v6.is_none() {
        Err(new_io_error(
            "cant delete default route, default gateway not found",
        ))
    } else {
        result
    }
}
