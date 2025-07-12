use ipnet::IpNet;
use tracing::warn;

use crate::{
    app::net::OutboundInterface, common::errors::new_io_error,
    config::internal::config::TunConfig,
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

fn run_ip_cmd(args: &[&str], enable_v6: bool) -> std::io::Result<()> {
    // IPv4
    let cmd_str = format!("ip {}", args.join(" "));
    let cmd = std::process::Command::new("ip").args(args).output()?;
    warn!("executing: {}", cmd_str);
    if !cmd.status.success() {
        return Err(new_io_error(format!(
            "{} failed: {}",
            cmd_str,
            String::from_utf8_lossy(&cmd.stderr)
        )));
    }

    // IPv6
    if enable_v6 {
        let mut v6_args = vec!["-6"];
        v6_args.extend_from_slice(args);
        let v6_cmd_str = format!("ip -6 {}", args.join(" "));
        let v6_cmd = std::process::Command::new("ip").args(&v6_args).output()?;
        warn!("executing: {}", v6_cmd_str);
        if !v6_cmd.status.success() {
            return Err(new_io_error(format!(
                "{} failed: {}",
                v6_cmd_str,
                String::from_utf8_lossy(&v6_cmd.stderr)
            )));
        }
    }

    Ok(())
}

/// three rules are added:
/// # ip route add default dev wg0 table 2468
/// # ip rule add not fwmark 1234 table 2468
/// # ip rule add table main suppress_prefixlength 0
/// for ipv6
/// # ip -6 ...
pub fn setup_policy_routing(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    let table = tun_cfg.route_table.to_string();
    let dev = via.name.as_str();
    let so_mark = tun_cfg.so_mark.to_string();
    let enable_v6 = tun_cfg.gateway_v6.is_some();

    run_ip_cmd(
        &["route", "add", "default", "dev", dev, "table", &table],
        enable_v6,
    )?;

    run_ip_cmd(
        &["rule", "add", "not", "fwmark", &so_mark, "table", &table],
        enable_v6,
    )?;

    run_ip_cmd(
        &["rule", "add", "table", "main", "suppress_prefixlength", "0"],
        enable_v6,
    )?;

    if tun_cfg.dns_hijack {
        run_ip_cmd(&["rule", "add", "dport", "53", "table", &table], enable_v6)?;
    }

    Ok(())
}

/// three rules to clean up:
/// # ip rule del not fwmark $SO_MARK table $TABLE
/// # ip rule del table main suppress_prefixlength 0
/// # ip rule del dport 53 table $TABLE
/// for v6
/// # ip -6 ...
pub fn maybe_routes_clean_up(tun_cfg: &TunConfig) -> std::io::Result<()> {
    if !(tun_cfg.enable && tun_cfg.route_all) {
        return Ok(());
    }

    let table = tun_cfg.route_table.to_string();
    let so_mark = tun_cfg.so_mark.to_string();
    let enable_v6 = tun_cfg.gateway_v6.is_some();

    run_ip_cmd(
        &["rule", "del", "not", "fwmark", &so_mark, "table", &table],
        enable_v6,
    )?;
    run_ip_cmd(
        &["rule", "del", "table", "main", "suppress_prefixlength", "0"],
        enable_v6,
    )?;

    if tun_cfg.dns_hijack {
        run_ip_cmd(&["rule", "del", "dport", "53", "table", &table], enable_v6)?;
    }

    Ok(())
}
