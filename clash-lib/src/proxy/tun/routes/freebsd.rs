use ipnet::IpNet;
use tracing::{info, warn};

use crate::{
    app::net::OutboundInterface, common::errors::new_io_error,
    config::internal::config::TunConfig,
};

/// FreeBSD uses FIBs (Forwarding Information Bases) for multiple routing
/// tables instead of Linux's policy routing (`ip rule` + `fwmark`).
///
/// The scheme mirrors the Linux implementation but with FIB semantics:
///   * FIB 0 (the default routing table used by every unprivileged process)
///     gets a default route pointing at the tun interface, so all traffic of
///     unrelated processes on the host is captured by clash.
///   * A separate "bypass" FIB (selected by `route_table`, default 2468) is
///     populated with a copy of the host's *original* default route (the real
///     gateway). clash's own outbound sockets are pushed into this bypass FIB
///     via `setfib(2)` so the proxy's traffic escapes through the physical
///     gateway instead of looping back into the tun.
///
/// Because `setfib(2)` sets the FIB for the whole process (and applies to all
/// sockets opened afterwards, regardless of thread), it is enough to call it
/// once after the tun is up and before any proxy traffic is forwarded; there
/// is no need to plumb a per-socket option through every outbound connector.
///
/// `net.fibs` may only be raised at runtime (never lowered) and is capped at
/// 65536. We raise it to `bypass_fib + 1` if it is not already large enough.
/// Production deployments that want a small number of FIBs should pick a small
/// `route_table` value and/or pre-set `net.fibs` in `/boot/loader.conf`.

/// Routing-table state we persist to disk so clean-up can restore the original
/// default route even after a crash / kill -9.
fn state_file() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push("clash-rs-fib-tun.state");
    p
}

#[derive(Debug, Default, Clone)]
struct FibState {
    tun_name: Option<String>,
    fib: Option<u32>,
    gw4: Option<String>,
    gw6: Option<String>,
    /// true if setup moved FIB 0's default route onto the tun (route_all). When
    /// false (partial mode) cleanup must NOT reinstall a default route in FIB 0
    /// since it was never moved.
    route_all: bool,
}

impl FibState {
    fn save(&self) -> std::io::Result<()> {
        let mut s = String::new();
        if let Some(n) = &self.tun_name {
            s.push_str(&format!("tun={n}\n"));
        }
        if let Some(f) = self.fib {
            s.push_str(&format!("fib={f}\n"));
        }
        if let Some(g) = &self.gw4 {
            s.push_str(&format!("gw4={g}\n"));
        }
        if let Some(g) = &self.gw6 {
            s.push_str(&format!("gw6={g}\n"));
        }
        s.push_str(&format!("route_all={}\n", self.route_all));
        std::fs::write(state_file(), s)
    }

    fn load() -> Option<FibState> {
        let s = std::fs::read_to_string(state_file()).ok()?;
        let mut st = FibState::default();
        for line in s.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k {
                    "tun" => st.tun_name = Some(v.to_string()),
                    "fib" => st.fib = v.parse().ok(),
                    "gw4" => st.gw4 = Some(v.to_string()),
                    "gw6" => st.gw6 = Some(v.to_string()),
                    "route_all" => st.route_all = v == "true",
                    _ => {}
                }
            }
        }
        Some(st)
    }

    fn remove() {
        let _ = std::fs::remove_file(state_file());
    }
}

/// Self-heal a stale routing state at startup.
///
/// clash's `TunRunner::shutdown()` (which calls [`maybe_routes_clean_up`]) is
/// only invoked via the external controller/IPC, *not* on SIGTERM / SIGINT /
/// `kill -9`. So if the previous clash process was killed mid-run, the FIB
/// tables are left dirty:
///   * FIB 0's default may still point at the (now-destroyed) tun, leaving
///     the host with no usable default route — even `route get default` fails,
///     which would make a fresh [`setup_policy_routing`] abort with
///     "requires an existing IPv4 default route".
///   * the bypass FIB may still hold the old gateway/default routes.
///
/// To break that deadlock, every tun setup first checks for a leftover state
/// file. If one exists, this function restores FIB 0's default from the saved
/// gateway (so the host regains connectivity and the bypass FIB is clean),
/// removes the stale state, and lets the caller proceed with a fresh setup.
/// It is best-effort: a missing/None gateway is skipped rather than fatal.
fn restore_stale_state(prev: &FibState) {
    let bypass_fib = prev.fib.unwrap_or(0);
    if prev.route_all {
        if let Some(gw4) = &prev.gw4 {
            let _ = run(std::process::Command::new("route")
                .arg("delete")
                .arg("default"));
            let _ = run(std::process::Command::new("route")
                .arg("add")
                .arg("default")
                .arg(gw4));
            info!(
                "freebsd tun self-heal: restored FIB 0 IPv4 default -> {}",
                gw4
            );
        }
        if let Some(gw6) = &prev.gw6 {
            let _ = run(std::process::Command::new("route")
                .arg("-6")
                .arg("delete")
                .arg("default"));
            let _ = run(std::process::Command::new("route")
                .arg("-6")
                .arg("add")
                .arg("default")
                .arg(gw6));
        }
    }
    if let Some(gw4) = &prev.gw4 {
        let _ = run(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("delete")
            .arg("default"));
        let _ = run(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("delete")
            .arg("-host")
            .arg(gw4));
    }
    if let Some(gw6) = &prev.gw6 {
        let _ = run(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("-6")
            .arg("delete")
            .arg("default"));
        let _ = run(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("-6")
            .arg("delete")
            .arg("-host")
            .arg(gw6));
    }
    FibState::remove();
    info!(
        "freebsd tun self-heal: cleaned stale state (route_all={}, fib={})",
        prev.route_all, bypass_fib
    );
}

/// Wrap a Command, execute it, log the invocation and return an io::Error on
/// failure with the captured stderr.
fn run(cmd: &mut std::process::Command) -> std::io::Result<()> {
    let cmd_str = format!(
        "{} {}",
        cmd.get_program().to_string_lossy(),
        cmd.get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ")
    );
    warn!("executing: {}", cmd_str);
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(new_io_error(format!(
            "{} failed: {}",
            cmd_str,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

/// Like [`run`] but tolerates "File exists" / "already exists" / EEXIST — i.e.
/// the route is already installed from a previous run that did not clean up
/// (crash, kill -9, or a dirty routing table). Idempotent re-installs are the
/// expected case for tun setup, not an error.
fn run_idempotent(cmd: &mut std::process::Command) -> std::io::Result<()> {
    let cmd_str = format!(
        "{} {}",
        cmd.get_program().to_string_lossy(),
        cmd.get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ")
    );
    warn!("executing: {}", cmd_str);
    let out = cmd.output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let s = stderr.to_ascii_lowercase();
        if s.contains("file exists")
            || s.contains("already exists")
            || s.contains("already in table")
        {
            info!("{} (already present, ignoring)", cmd_str);
            return Ok(());
        }
        return Err(new_io_error(format!("{} failed: {}", cmd_str, stderr)));
    }
    Ok(())
}

// `libc::setfib` is not re-exported by the `libc` crate, so declare the
// symbol directly (it lives in libc, which clash links against).
unsafe extern "C" {
    fn setfib(fib: std::ffi::c_int) -> std::ffi::c_int;
}

fn set_process_fib(fib: u32) -> std::io::Result<()> {
    // SAFETY: `setfib(2)` simply stores the integer in the process/thread
    // control block; it does not read user memory and is always safe to call
    // with an in-range value (EINVAL otherwise).
    let rc = unsafe { setfib(fib as std::ffi::c_int) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(new_io_error(format!("setfib({}) failed: {}", fib, err)));
    }
    info!("process default FIB set to {}", fib);
    Ok(())
}

fn current_fibs() -> u32 {
    std::process::Command::new("sysctl")
        .arg("-n")
        .arg("net.fibs")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
            } else {
                None
            }
        })
        .unwrap_or(1)
}

fn ensure_fibs(needed: u32) -> std::io::Result<()> {
    let cur = current_fibs();
    if cur >= needed {
        return Ok(());
    }
    run(std::process::Command::new("sysctl")
        .arg("-w")
        .arg(format!("net.fibs={}", needed)))
}

/// Like [`default_gateway`] but also returns the outgoing interface name the
/// kernel uses to reach that gateway. The bypass FIB needs the latter to make
/// the gateway on-link before installing a `default -> <gw>` route (otherwise
/// `setfib N route add default <gw>` fails with `Invalid argument` because the
/// new FIB has no on-link subnet entry to resolve the gateway).
fn default_gateway_and_iface(ipv6: bool) -> Option<(String, String)> {
    let mut cmd = std::process::Command::new("route");
    if ipv6 {
        cmd.arg("-6");
    }
    cmd.arg("-n").arg("get").arg("default");
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut gw: Option<String> = None;
    let mut iface: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("gateway:") {
            let g = rest.trim().to_string();
            if !g.is_empty() {
                gw = Some(g);
            }
        } else if let Some(rest) = line.strip_prefix("interface:") {
            let i = rest.trim().to_string();
            if !i.is_empty() {
                iface = Some(i);
            }
        }
    }
    match (gw, iface) {
        (Some(g), Some(i)) => Some((g, i)),
        _ => None,
    }
}

/// Ensure the FreeBSD tun/tap network interface (and its `/dev/<name>` device
/// node) exists before [`tun_rs`] tries to `open()` it.
///
/// Background: on FreeBSD the `/dev/tun<N>` (and `/dev/tap<N>`) character
/// device nodes are **not** static. They are materialised by devfs only while
/// the matching network interface exists — i.e. after `ifconfig <name>
/// create` (and they disappear again on `destroy`).
///
/// `tun-rs`'s `DeviceBuilder::build_async()` on FreeBSD resolves a named device
/// like `tun0` to `/dev/tun0` and calls `open("/dev/tun0", O_RDWR)` directly
/// without creating the interface first. If the interface does not already
/// exist, that `open()` fails with `ENOENT` ("No such file or directory"),
/// which bubbles up as `tun initialization I/O error: No such file or
/// directory (os error 2)` from `TunRunner::new_internal`.
///
/// Pre-creating the interface here fixes that. We deliberately ignore the
/// "interface already exists" message because the caller only invokes this
/// when it has decided the interface is missing, but a parallel creator (or a
/// leftover from a previous run) could race us. Any other error is fatal —
/// tun creation is a prerequisite for everything that follows.
pub fn ensure_tun_device(name: &str) -> std::io::Result<()> {
    let out = std::process::Command::new("ifconfig")
        .arg(name)
        .arg("create")
        .output()?;
    if out.status.success() {
        info!("freebsd: created tun interface {} (dev node materialised)", name);
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // "interface already exists" — benign, someone else created it.
    if stderr.contains("already exists") {
        info!(
            "freebsd: tun interface {} already exists (ifconfig create noop)",
            name
        );
        return Ok(());
    }
    Err(new_io_error(format!(
        "ifconfig {} create failed: {}",
        name,
        stderr.trim()
    )))
}

/// Per-destination route used when `route_all` is disabled (the same role as
/// the Linux `add_route`). Adds an interface route into the default FIB 0.
pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let ipv6 = matches!(dest, IpNet::V6(_));
    let mut cmd = std::process::Command::new("route");
    if ipv6 {
        cmd.arg("-6");
    }
    cmd.arg("add")
        .arg(dest.to_string())
        .arg("-interface")
        .arg(&via.name);
    run_idempotent(&mut cmd)?;
    Ok(())
}

/// Install `default -> <real gateway>` into the bypass FIB so that clash (which
/// runs inside that FIB) can reach the internet directly. Shared by both
/// full-tun (`route_all`) and partial-tun modes.
///
/// Because the bypass FIB starts empty (it has none of FIB 0's on-link subnet
/// routes), adding a `default -> <gw>` route would fail with `Invalid
/// argument` (the kernel can't resolve the gateway). We therefore first install
/// a host route marking the gateway as on-link via the original outgoing
/// interface, then add the default route.
fn install_bypass_default(
    bypass_fib: u32,
    gw4: &str,
    iface4: &str,
    gw6: Option<&str>,
    iface6: Option<&str>,
) -> std::io::Result<()> {
    // All installs are idempotent: a dirty bypass FIB (left over from a
    // previous run that crashed or was kill -9'd) may already hold these
    // routes; re-installing must not fail with EEXIST.
    run_idempotent(std::process::Command::new("setfib")
        .arg(bypass_fib.to_string())
        .arg("route")
        .arg("add")
        .arg("-host")
        .arg(gw4)
        .arg("-interface")
        .arg(iface4))?;
    run_idempotent(std::process::Command::new("setfib")
        .arg(bypass_fib.to_string())
        .arg("route")
        .arg("add")
        .arg("default")
        .arg(gw4))?;
    if let (Some(gw6), Some(iface6)) = (gw6, iface6) {
        if run_idempotent(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("-6")
            .arg("add")
            .arg("-host")
            .arg(gw6)
            .arg("-interface")
            .arg(iface6))
            .is_err()
        {
            warn!(
                "failed to install IPv6 gateway host route into bypass FIB {} \
                 (non-fatal)",
                bypass_fib
            );
        }
        if run_idempotent(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("-6")
            .arg("add")
            .arg("default")
            .arg(gw6))
            .is_err()
        {
            warn!(
                "failed to install IPv6 default route into bypass FIB {} \
                 (non-fatal)",
                bypass_fib
            );
        }
    }
    Ok(())
}

/// Tear down [`install_bypass_default`] in best-effort fashion (used by both
/// full-tun crashes and clean shutdown).
#[allow(dead_code)]
fn uninstall_bypass_default(
    bypass_fib: u32,
    gw4: &str,
    gw6: Option<&str>,
) {
    let _ = run(std::process::Command::new("setfib")
        .arg(bypass_fib.to_string())
        .arg("route")
        .arg("delete")
        .arg("default"));
    let _ = run(std::process::Command::new("setfib")
        .arg(bypass_fib.to_string())
        .arg("route")
        .arg("delete")
        .arg("-host")
        .arg(gw4));
    if let Some(gw6) = gw6 {
        let _ = run(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("-6")
            .arg("delete")
            .arg("default"));
        let _ = run(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("-6")
            .arg("delete")
            .arg("-host")
            .arg(gw6));
    }
}

/// FIB-based policy routing, the FreeBSD analogue of Linux's
/// `setup_policy_routing` (used when `route_all` is true).
///
/// State is persisted so crashes can be cleaned up and a relaunch is
/// idempotent: if a previous run left the routing tables already migrated we
/// reuse the saved original gateway instead of re-reading (now incorrect)
/// `route get default`, which by then points at the tun.
pub fn setup_policy_routing(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    let bypass_fib = tun_cfg.route_table;
    let tun_name = via.name.clone();
    let enable_v6 = tun_cfg.gateway_v6.is_some();

    // Self-heal: a previous clash run that was killed (SIGTERM / kill -9)
    // would not have run maybe_routes_clean_up, so the FIB tables may be dirty
    // and FIB 0's default may be gone. Restore from the saved state first so
    // we can read the real gateway below, then proceed with a fresh setup.
    if let Some(prev) = FibState::load() {
        info!(
            "freebsd fib tun: found leftover state from previous run \
             (tun={}, fib={}, gw4={}); restoring before fresh setup",
            prev.tun_name.as_deref().unwrap_or(&tun_name),
            prev.fib.unwrap_or(bypass_fib),
            prev.gw4.as_deref().unwrap_or("?"),
        );
        restore_stale_state(&prev);
    }

    // Capture the real default gateway *and* the outgoing interface *before*
    // we touch FIB 0 — the bypass FIB needs the interface to mark the gateway
    // on-link (see `install_bypass_default`).
    let (gw4, iface4) = default_gateway_and_iface(false).ok_or_else(|| {
        new_io_error(
            "freebsd tun route_all requires an existing IPv4 default route \
             to back up into the bypass FIB"
                .to_string(),
        )
    })?;
    let (gw6, iface6) = if enable_v6 {
        match default_gateway_and_iface(true) {
            Some((g, i)) => (Some(g), Some(i)),
            None => (None, None),
        }
    } else {
        (None, None)
    };

    ensure_fibs(bypass_fib + 1)?;

    // Switch FIB 0 (default routing table) over to the tun interface. The
    // `add` is idempotent in case FIB 0 default already points at the tun
    // (e.g. a previous run crashed after moving it but before writing state).
    let _ = run(std::process::Command::new("route")
        .arg("delete")
        .arg("default"));
    run_idempotent(std::process::Command::new("route")
        .arg("add")
        .arg("default")
        .arg("-interface")
        .arg(&tun_name))?;

    // If installing the bypass default fails we must roll FIB 0's default route
    // back so the host does NOT lose connectivity (the most expensive mistake
    // this module can make).
    if let Err(e) = install_bypass_default(
        bypass_fib,
        &gw4,
        &iface4,
        gw6.as_deref(),
        iface6.as_deref(),
    ) {
        warn!("install_bypass_default failed, rolling FIB 0 default back: {e}");
        let _ = run(std::process::Command::new("route")
            .arg("delete")
            .arg("default"));
        let _ = run(std::process::Command::new("route")
            .arg("add")
            .arg("default")
            .arg(&gw4));
        return Err(e);
    }

    FibState {
        tun_name: Some(tun_name.clone()),
        fib: Some(bypass_fib),
        gw4: Some(gw4),
        gw6,
        route_all: true,
    }
    .save()?;

    // Push the whole clash process onto the bypass FIB so every outbound socket
    // it opens hereafter uses the physical gateway directly (no tun loop).
    set_process_fib(bypass_fib)?;

    Ok(())
}

/// Partial-tun setup: like `setup_policy_routing` but leaves FIB 0's default
/// route untouched. Only the per-listed `routes` (already added to FIB 0 by the
/// caller via `add_route`) are funnelled into the tun; everything else on the
/// host still uses the normal default route. clash itself is moved onto the
/// bypass FIB so its own DIRECT outbounds escape via the physical gateway
/// instead of looping back through the tun for the captured destinations.
///
/// This is the FreeBSD equivalent of Linux's `routes: [...]+ fwmark` rollback
/// (FreeBSD has no fwmark, so we lean on FIBs instead).
pub fn setup_partial_fib(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    let bypass_fib = tun_cfg.route_table;
    let tun_name = via.name.clone();
    let enable_v6 = tun_cfg.gateway_v6.is_some();

    // Self-heal any stale state from a previous killed run before doing a
    // fresh partial setup (see restore_stale_state for why).
    if let Some(prev) = FibState::load() {
        info!(
            "freebsd fib tun (partial): found leftover state \
             (tun={}, fib={}, gw4={}); restoring before fresh setup",
            prev.tun_name.as_deref().unwrap_or(&tun_name),
            prev.fib.unwrap_or(bypass_fib),
            prev.gw4.as_deref().unwrap_or("?"),
        );
        restore_stale_state(&prev);
    }

    let (gw4, iface4) = default_gateway_and_iface(false).ok_or_else(|| {
        new_io_error(
            "freebsd tun (partial) requires an existing IPv4 default route to \
             back up into the bypass FIB"
                .to_string(),
        )
    })?;
    let (gw6, iface6) = if enable_v6 {
        match default_gateway_and_iface(true) {
            Some((g, i)) => (Some(g), Some(i)),
            None => (None, None),
        }
    } else {
        (None, None)
    };

    ensure_fibs(bypass_fib + 1)?;
    // Partial mode never moved FIB 0's default, so there is nothing to roll
    // back on failure — just propagate the error.
    install_bypass_default(
        bypass_fib,
        &gw4,
        &iface4,
        gw6.as_deref(),
        iface6.as_deref(),
    )?;

    FibState {
        tun_name: Some(tun_name.clone()),
        fib: Some(bypass_fib),
        gw4: Some(gw4),
        gw6,
        route_all: false,
    }
    .save()?;

    set_process_fib(bypass_fib)?;
    Ok(())
}

/// Reverse the FIB setup performed by `setup_policy_routing` /
/// `setup_partial_fib`: drop the bypass-FIB default route, and (only for the
/// full `route_all` case, where we moved FIB 0's default onto the tun) restore
/// the original default route in FIB 0. Best-effort — missing state means a
/// clean-up was already performed (or setup never happened), which is fine.
pub fn maybe_routes_clean_up(tun_cfg: &TunConfig) -> std::io::Result<()> {
    if !tun_cfg.enable {
        return Ok(());
    }

    let Some(state) = FibState::load() else {
        warn!(
            "freebsd tun clean-up: no persisted state, nothing to restore \
             (already clean or setup never completed)"
        );
        return Ok(());
    };
    let bypass_fib = state.fib.or(Some(tun_cfg.route_table)).unwrap_or(0);

    // Restore the original IPv4/IPv6 default route in FIB 0 *only* if we
    // actually moved it during setup (route_all). Partial mode leaves FIB 0's
    // default untouched, so reinstalling here would duplicate an existing
    // route and produce "route already in table" noise.
    if state.route_all {
        let _ =
            run(std::process::Command::new("route").arg("delete").arg("default"));
        if let Some(gw4) = &state.gw4 {
            run(std::process::Command::new("route")
                .arg("add")
                .arg("default")
                .arg(gw4))?;
        }
        if let Some(gw6) = &state.gw6 {
            let _ = run(std::process::Command::new("route")
                .arg("-6")
                .arg("delete")
                .arg("default"));
            let _ = run(std::process::Command::new("route")
                .arg("-6")
                .arg("add")
                .arg("default")
                .arg(gw6));
        }
    }

    // Drop the bypass-FIB default route(s) installed by both modes, plus the
    // on-link host route(s) we added for the gateways (see install_bypass_default).
    if let Some(gw4) = &state.gw4 {
        let _ = run(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("delete")
            .arg("default"));
        let _ = run(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("delete")
            .arg("-host")
            .arg(gw4));
    }
    if let Some(gw6) = &state.gw6 {
        let _ = run(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("-6")
            .arg("delete")
            .arg("default"));
        let _ = run(std::process::Command::new("setfib")
            .arg(bypass_fib.to_string())
            .arg("route")
            .arg("-6")
            .arg("delete")
            .arg("-host")
            .arg(gw6));
    }

    // Reset clash's own process FIB back to 0 (no-op at shutdown, but tidy).
    let _ = set_process_fib(0);

    FibState::remove();
    info!(
        "freebsd tun routing cleaned up (fib {} restored to 0, route_all={})",
        bypass_fib, state.route_all
    );
    Ok(())
}