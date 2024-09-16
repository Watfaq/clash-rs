use std::net::Ipv4Addr;

use ipnet::IpNet;
use tracing::warn;

use crate::{
    common::errors::new_io_error,
    proxy::utils::{get_outbound_interface, OutboundInterface},
};

/// let's assume that the `route` command is available on macOS
pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let cmd = std::process::Command::new("route")
        .arg("add")
        .arg("-net")
        .arg(&dest.to_string())
        .arg("-interface")
        .arg(&via.name)
        .output()?;

    warn!("executing: route add -net {} -interface {}", dest, via.name);
    if !cmd.status.success() {
        Err(new_io_error("add route failed"))
    } else {
        Ok(())
    }
}

fn get_default_gateway() -> std::io::Result<Option<Ipv4Addr>> {
    let cmd = std::process::Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("default")
        .output()?;

    if !cmd.status.success() {
        return Ok(None);
    }

    let output = String::from_utf8_lossy(&cmd.stdout);

    let mut gateway = None;
    for line in output.lines() {
        if line.trim().contains("gateway:") {
            gateway = line
                .split_whitespace()
                .last()
                .and_then(|x| x.parse::<Ipv4Addr>().ok());
            break;
        }
    }

    Ok(gateway)
}

/// it seems to be fine to add the default route multiple times
pub fn maybe_add_default_route() -> std::io::Result<()> {
    let gateway = get_default_gateway()?;
    if let Some(gateway) = gateway {
        let default_interface =
            get_outbound_interface().ok_or(new_io_error("get default interface"))?;

        let cmd = std::process::Command::new("route")
            .arg("add")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("0/0")
            .arg(&gateway.to_string())
            .output()?;

        warn!(
            "executing: route add -ifscope {} 0/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            Err(new_io_error("add default route failed"))
        } else {
            Ok(())
        }
    } else {
        Err(new_io_error(
            "cant set default route, default gateway not found",
        ))
    }
}

/// failing to delete the default route won't cause route failure
pub fn del_default_route() -> std::io::Result<()> {
    let gateway = get_default_gateway()?;
    if let Some(gateway) = gateway {
        let default_interface =
            get_outbound_interface().ok_or(new_io_error("get default interface"))?;
        let cmd = std::process::Command::new("route")
            .arg("delete")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("0/0")
            .arg(&gateway.to_string())
            .output()?;

        warn!(
            "executing: route delete -ifscope {} 0/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            Err(new_io_error("delete default route failed"))
        } else {
            Ok(())
        }
    } else {
        Err(new_io_error(
            "cant delete default route, default gateway not found",
        ))
    }
}
