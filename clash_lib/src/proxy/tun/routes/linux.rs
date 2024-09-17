use ipnet::IpNet;
use tracing::warn;

use crate::{
    common::errors::new_io_error, config::internal::config::TunConfig,
    proxy::utils::OutboundInterface,
};

/// TODO: get rid of command execution
pub fn check_ip_command_installed() -> std::io::Result<()> {
    std::process::Command::new("ip")
        .arg("route")
        .output()
        .and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "ip command not found",
                ))
            }
        })
}

pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let cmd = std::process::Command::new("ip")
        .arg("route")
        .arg("add")
        .arg(dest.to_string())
        .arg("dev")
        .arg(&via.name)
        .output()?;
    warn!("executing: ip route add {} dev {}", dest, via.name);
    if !cmd.status.success() {
        return Err(new_io_error(format!(
            "add route failed: {}",
            String::from_utf8_lossy(&cmd.stderr)
        )));
    }
    Ok(())
}

/// three rules are added:
/// # ip route add default dev wg0 table 2468
/// # ip rule add not fwmark 1234 table 2468
/// # ip rule add table main suppress_prefixlength 0
pub fn setup_policy_routing(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    let cmd = std::process::Command::new("ip")
        .arg("route")
        .arg("add")
        .arg("default")
        .arg("dev")
        .arg(via.name.as_str())
        .arg("table")
        .arg(
            tun_cfg
                .route_table
                .expect("route_table not set")
                .to_string(),
        )
        .output()?;
    warn!(
        "executing: ip route add default dev {} table {}",
        via.name,
        tun_cfg.route_table.unwrap()
    );
    if !cmd.status.success() {
        return Err(new_io_error(format!(
            "add default route failed: {}",
            String::from_utf8_lossy(&cmd.stderr)
        )));
    }

    let cmd = std::process::Command::new("ip")
        .arg("rule")
        .arg("add")
        .arg("not")
        .arg("fwmark")
        .arg(tun_cfg.so_mark.expect("so_mark not set").to_string())
        .arg("table")
        .arg(
            tun_cfg
                .route_table
                .expect("route_table not set")
                .to_string(),
        )
        .output()?;
    warn!(
        "executing: ip rule add not fwmark {} table {}",
        tun_cfg.so_mark.unwrap(),
        tun_cfg.route_table.unwrap()
    );
    if !cmd.status.success() {
        return Err(new_io_error(format!(
            "add rule failed: {}",
            String::from_utf8_lossy(&cmd.stderr)
        )));
    }

    let cmd = std::process::Command::new("ip")
        .arg("rule")
        .arg("add")
        .arg("table")
        .arg("main")
        .arg("suppress_prefixlength")
        .arg("0")
        .output()?;
    warn!("executing: ip rule add table main suppress_prefixlength 0");
    if !cmd.status.success() {
        return Err(new_io_error(format!(
            "add rule failed: {}",
            String::from_utf8_lossy(&cmd.stderr)
        )));
    }

    Ok(())
}

/// three rules to clean up:
/// # ip rule add not fwmark $SO_MARK table $TABLE
/// # ip rule add table main suppress_prefixlength 0
pub fn maybe_routes_clean_up(tun_cfg: &TunConfig) -> std::io::Result<()> {
    let cmd = std::process::Command::new("ip")
        .arg("rule")
        .arg("del")
        .arg("not")
        .arg("fwmark")
        .arg(tun_cfg.so_mark.expect("so_mark not set").to_string())
        .arg("table")
        .arg(
            tun_cfg
                .route_table
                .expect("route_table not set")
                .to_string(),
        )
        .output()?;
    warn!(
        "executing: ip rule del not fwmark {} table {}",
        tun_cfg.so_mark.unwrap(),
        tun_cfg.route_table.unwrap()
    );
    if !cmd.status.success() {
        return Err(new_io_error(format!(
            "delete rule failed: {}",
            String::from_utf8_lossy(&cmd.stderr)
        )));
    }

    let cmd = std::process::Command::new("ip")
        .arg("rule")
        .arg("del")
        .arg("table")
        .arg("main")
        .arg("suppress_prefixlength")
        .arg("0")
        .output()?;

    warn!("executing: ip rule del table main suppress_prefixlength 0");
    if !cmd.status.success() {
        return Err(new_io_error(format!(
            "delete rule failed: {}",
            String::from_utf8_lossy(&cmd.stderr)
        )));
    }
    Ok(())
}
