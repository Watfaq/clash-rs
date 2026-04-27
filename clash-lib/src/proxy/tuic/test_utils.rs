use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::sync::oneshot;

/// A running tuic-server instance that cleans up on drop.
pub struct TuicServerProcess {
    handle: Option<tokio::task::JoinHandle<()>>,
    port: u16,
}

impl TuicServerProcess {
    /// Start a tuic-server instance on a random port.
    pub async fn start() -> anyhow::Result<Self> {
        let port = alloc_port();
        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;

        let cfg = tuic_server::Config {
            server: server_addr,
            log_level: tuic_server::config::LogLevel::Info,
            users: HashMap::from([(
                "00000000-0000-0000-0000-000000000001".parse()?,
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

        let (ready_tx, ready_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
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
            });
            match tuic_server::server::Server::init(ctx).await {
                Ok(server) => {
                    let _ = ready_tx.send(());
                    server.start().await;
                }
                Err(e) => {
                    tracing::error!("tuic-server init failed: {e}");
                    let _ = ready_tx.send(());
                }
            }
        });

        // Wait for the server to be ready
        tokio::time::timeout(Duration::from_secs(30), ready_rx)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "tuic-server failed to start on port {port} within 30s"
                )
            })?
            .ok();

        // Wait a brief moment for the socket to be fully bound
        tokio::time::sleep(Duration::from_millis(100)).await;

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

/// Allocate a free UDP port (tuic works over QUIC/UDP).
fn alloc_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("failed to allocate a free port");
    socket.local_addr().unwrap().port()
}
