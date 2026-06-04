use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// A running tuic-server instance that cleans up on drop.
pub struct TuicServerProcess {
    handle: Option<tokio::task::JoinHandle<()>>,
    port: u16,
}

impl TuicServerProcess {
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with_config("127.0.0.1:0", false, false).await
    }

    pub async fn start_v6() -> anyhow::Result<Self> {
        Self::start_with_config("[::1]:0", false, false).await
    }

    pub async fn start_dual_stack() -> anyhow::Result<Self> {
        Self::start_with_config("[::]:0", true, true).await
    }

    async fn start_with_config(
        server_bind: &'static str,
        dual_stack: bool,
        udp_relay_ipv6: bool,
    ) -> anyhow::Result<Self> {
        let (port_tx, port_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = oneshot::channel::<anyhow::Result<()>>();

        let handle = tokio::spawn(async move {
            let cfg = tuic_server::Config {
                server: server_bind.parse().unwrap(),
                log_level: tuic_server::config::LogLevel::Info,
                users: HashMap::from([(
                    "00000000-0000-0000-0000-000000000001".parse().unwrap(),
                    "passwd".into(),
                )]),
                tls: tuic_server::config::TlsConfig {
                    self_sign: true,
                    hostname: "localhost".into(),
                    alpn: vec!["h3".into()],
                    ..Default::default()
                },
                zero_rtt_handshake: false,
                dual_stack,
                outbound: tuic_server::config::OutboundConfig {
                    default: tuic_server::config::OutboundRule {
                        kind: "direct".into(),
                        ..Default::default()
                    },
                    named: HashMap::new(),
                },
                acl: vec![],
                udp_relay_ipv6,
                experimental: tuic_server::config::ExperimentalConfig {
                    drop_loopback: false,
                    drop_private: false,
                },
                ..Default::default()
            };

            let mut online_counter = HashMap::new();
            for (user, _) in cfg.users.iter() {
                online_counter
                    .insert(user.to_owned(), std::sync::atomic::AtomicUsize::new(0));
            }
            let mut traffic_stats = HashMap::new();
            for (user, _) in cfg.users.iter() {
                traffic_stats.insert(
                    user.to_owned(),
                    (
                        std::sync::atomic::AtomicUsize::new(0),
                        std::sync::atomic::AtomicUsize::new(0),
                    ),
                );
            }
            let capacity = cfg.users.len() as u64;
            let ctx = Arc::new(tuic_server::AppContext {
                cfg,
                online_counter,
                online_clients: moka::future::Cache::new(capacity),
                traffic_stats,
                cancel: CancellationToken::new(),
            });
            match tuic_server::server::Server::init(ctx).await {
                Ok(server) => {
                    let port = server.local_addr().unwrap().port();
                    let _ = port_tx.send(port);
                    let _ = ready_tx.send(Ok(()));
                    server.start().await;
                }
                Err(e) => {
                    tracing::error!("tuic-server init failed: {e}");
                    let _ = ready_tx.send(Err(anyhow::anyhow!("{e}")));
                }
            }
        });

        let port = tokio::time::timeout(Duration::from_secs(5), port_rx)
            .await
            .map_err(|_| anyhow::anyhow!("tuic-server failed to report a port"))?
            .map_err(|_| {
                anyhow::anyhow!("tuic-server task panicked before reporting port")
            })?;

        tokio::time::timeout(Duration::from_secs(30), ready_rx)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "tuic-server failed to start on port {port} within 30s"
                )
            })?
            .map_err(|e| anyhow::anyhow!("tuic-server init failed: {e}"))??;

        tracing::info!("tuic-server started on port {port}");

        Ok(Self {
            handle: Some(handle),
            port,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for TuicServerProcess {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            tracing::info!("tuic-server task aborted");
        }
    }
}

/// Detect that the test binary is running under qemu-user emulation (i.e.
/// `cross test` on a non-native target). QUIC under qemu-user is unreliable
/// — packet timing, MTU discovery and timers all drift enough that the TUIC
/// stream ping-pong races against the idle / request timeouts and the stream
/// gets reset mid-relay. We use this to skip the relay tests on cross-built
/// targets while keeping native arch coverage (Linux x86_64, macOS aarch64).
///
/// The signal: under qemu-user the binary's compile-time `target_arch` differs
/// from the kernel's reported `utsname.machine`. Native runs match.
#[cfg(unix)]
pub fn running_under_qemu_user() -> bool {
    use std::ffi::CStr;

    // SAFETY: `uname` writes into a zeroed `utsname` and returns 0 on success.
    let mut uts = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return false;
    }
    let machine_ptr = uts.machine.as_ptr() as *const std::os::raw::c_char;
    let host = match unsafe { CStr::from_ptr(machine_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let target = std::env::consts::ARCH;
    !arch_matches(target, host)
}

#[cfg(not(unix))]
pub fn running_under_qemu_user() -> bool {
    false
}

#[cfg(unix)]
fn arch_matches(target: &str, host: &str) -> bool {
    match target {
        "x86_64" => host == "x86_64" || host == "amd64",
        "x86" => host == "i386" || host == "i686",
        "aarch64" => host == "aarch64" || host == "arm64",
        "arm" => host.starts_with("arm"),
        "riscv64" => host == "riscv64",
        "powerpc64" => host == "ppc64" || host == "ppc64le",
        "powerpc" => host == "ppc",
        "mips" => host == "mips",
        "mips64" => host == "mips64",
        "s390x" => host == "s390x",
        _ => target == host,
    }
}

/// Skip the current test (with an explanatory message) when running under
/// qemu-user. Returns `true` if the caller should bail out early.
#[macro_export]
macro_rules! skip_under_qemu_user {
    ($name:expr) => {{
        if $crate::proxy::tuic::test_utils::running_under_qemu_user() {
            eprintln!(
                "skipping {} under qemu-user emulation (QUIC timing unreliable)",
                $name
            );
            return Ok(());
        }
    }};
}
