use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// A running tuic-server instance that cleans up on drop.
pub struct TuicServerProcess {
    handle: Option<tokio::task::JoinHandle<()>>,
    port: u16,
}

impl TuicServerProcess {
    /// Start a tuic-server instance on a random port.
    pub async fn start() -> anyhow::Result<Self> {
        // We use a channel to receive the actual bound port from the task.
        let (port_tx, port_rx) = oneshot::channel();

        let (ready_tx, ready_rx) = oneshot::channel::<anyhow::Result<()>>();

        let handle = tokio::spawn(async move {
            let cfg = tuic_server::Config {
                server: "127.0.0.1:0".parse().unwrap(),
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
                dual_stack: false,
                outbound: tuic_server::config::OutboundConfig {
                    default: tuic_server::config::OutboundRule {
                        kind: "direct".into(),
                        ..Default::default()
                    },
                    named: HashMap::new(),
                },
                acl: vec![],
                udp_relay_ipv6: false,
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

        // Wait for the server to be ready (or for init to fail).
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
