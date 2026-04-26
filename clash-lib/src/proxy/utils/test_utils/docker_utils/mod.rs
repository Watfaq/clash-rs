use self::docker_runner::RunAndCleanup;
use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, ChainedStream},
        remote_content_manager::ProxyManager,
    },
    proxy::{OutboundHandler, datagram::UdpPacket},
    session::{Session, SocksAddr},
};
use anyhow::{anyhow, bail};
use futures::{SinkExt, StreamExt, future::select_all};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use sysinfo::Networks;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split},
    net::{TcpListener, UdpSocket},
};
use tracing::{debug, info, trace};

// ── Port allocator
// ────────────────────────────────────────────────────────────
/// Allocate a free port by asking the OS for one. Each call returns a unique
/// port so parallel tests never collide with each other or with ephemeral
/// ports.
#[cfg(throughput_test)]
pub fn alloc_port() -> u16 {
    // Bind port 0 to let the OS pick a free port, then release it.
    // TOCTOU race is acceptable in test environments.
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("alloc_port: bind failed");
    listener
        .local_addr()
        .expect("alloc_port: local_addr")
        .port()
}

// ── ThroughputResult
// ──────────────────────────────────────────────────────────
#[cfg(throughput_test)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ThroughputResult {
    pub label: String,
    pub upload_mbps: f64,
    pub download_mbps: f64,
    pub total_bytes: usize,
}

/// Append one result line to the file named by `THROUGHPUT_RESULTS_FILE` (if
/// set).  Each line is a self-contained JSON object so the file can be parsed
/// incrementally even when multiple tests run in parallel.
#[cfg(all(docker_test, throughput_test))]
fn write_throughput_result(result: &ThroughputResult) {
    let Some(path) = std::env::var_os("THROUGHPUT_RESULTS_FILE") else {
        return;
    };
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("THROUGHPUT_RESULTS_FILE: cannot open for append");
    let mut line = serde_json::to_string(result)
        .expect("ThroughputResult serialization failed");
    line.push('\n');
    file.write_all(line.as_bytes())
        .expect("THROUGHPUT_RESULTS_FILE: write failed");
}

// ── find_clash_rs_binary
// ──────────────────────────────────────────────────────
/// Locate the clash-rs binary.  Prefers the debug build (faster iteration) and
/// falls back to the release build.  Panics if neither exists.
#[cfg(throughput_test)]
pub fn find_clash_rs_binary() -> std::path::PathBuf {
    let root = config_helper::root_dir();
    // Prefer the release binary: it's faster (important for throughput tests)
    // and avoids the `telemetry` feature deadlock that occurs when
    // `cargo build --all-features` is used (console_subscriber + OpenTelemetry
    // threads compete with the main thread over a mutex during crypto init).
    // Build with: cargo build --release --bin clash-rs
    let release = root.join("target/release/clash-rs");
    let debug = root.join("target/debug/clash-rs");
    if release.exists() {
        release
    } else if debug.exists() {
        debug
    } else {
        panic!(
            "clash-rs binary not found — run `cargo build --release --bin \
             clash-rs` first (do NOT use --all-features: the telemetry feature \
             causes startup deadlocks when multiple instances run concurrently)"
        )
    }
}

pub mod config_helper;
pub mod consts;
pub mod docker_runner;

fn destination_list(gateway_ip: Option<String>) -> Vec<String> {
    let mut destination_list = vec!["host.docker.internal".to_owned()];
    if let Some(ip) = gateway_ip {
        debug!("gateway_ip Ip: {}", ip);
        destination_list.push(ip);
    }
    if let Some(ip) = std::env::var("CLIENT_IP").ok() {
        debug!("client Ip: {}", &ip);
        destination_list.insert(0, ip);
    } else {
        debug!("CLIENT_IP env not set, ");
        let mut networks = Networks::new_with_refreshed_list();
        networks.refresh(true);

        trace!("networks: {:?}", networks);
        // 收集所有有流量的网卡的 IPv4 地址
        let mut active_interfaces = networks
            .iter()
            .filter(|(_, data)| {
                data.mac_address().to_string() != "00:00:00:00:00:00"
            })
            .collect::<Vec<_>>();

        // 按流量排序：优先按发送流量降序，其次按接收流量降序
        active_interfaces.sort_by(|a, b| {
            b.1.total_transmitted()
                .cmp(&a.1.total_transmitted())
                .then_with(|| b.1.total_received().cmp(&a.1.total_received()))
        });
        for (iface_name, data) in active_interfaces {
            trace!("Processing interface: {}, {:#?}", iface_name, data);

            // 获取该网卡的所有 IP 地址
            for ip_network in data.ip_networks() {
                let addr = ip_network.addr;
                // 只添加 IPv4 地址，排除 loopback
                if addr.is_ipv4() && !addr.is_loopback() {
                    let ip_str = addr.to_string();
                    // 跳过已存在的 IP
                    if !destination_list.contains(&ip_str) {
                        debug!("Found IPv4 address on {}: {}", iface_name, ip_str);
                        destination_list.push(ip_str);
                    }
                }
            }
        }
    }
    destination_list
}

// TODO: add the throughput metrics
pub async fn ping_pong_test(
    handler: Arc<dyn OutboundHandler>,
    gateway_ip: Option<String>,
    port: u16,
) -> anyhow::Result<()> {
    // PATH: our proxy handler -> proxy-server(container) -> target local
    // server(127.0.0.1:port)

    let destination_list = destination_list(gateway_ip);

    let resolver = config_helper::build_dns_resolver().await?;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port).as_str()).await?;

    info!("target local server started at: {}", listener.local_addr()?);

    async fn destination_fn<T>(incoming: T) -> anyhow::Result<()>
    where
        T: AsyncRead + AsyncWrite,
    {
        // Use inbound_stream here
        let (mut read_half, mut write_half) = split(incoming);
        let chunk = "world";
        let mut buf = vec![0; 5];

        info!("destination_fn(tcp) start read");

        for _ in 0..100 {
            read_half.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"hello");
        }

        info!("destination_fn(tcp) start write");
        for _ in 0..100 {
            write_half.write_all(chunk.as_bytes()).await?;
            write_half.flush().await?;
        }

        info!("destination_fn(tcp) end");
        Ok(())
    }
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let target_local_server_handler = tokio::spawn(async move {
        let mut rx = rx;
        loop {
            tokio::select! {
                data = listener.accept() => {
                    match data {
                        Ok((stream, _)) => {
                            info!(
                                "Accepted connection(tcp) from: {:?}",
                                stream.peer_addr().ok()
                            );
                            if let Err(e) = destination_fn(stream).await {
                                info!("Error handling connection(tcp): {}", e);
                            }
                        },
                        Err(e) => {
                            info!("Error accepting connection(tcp): {}", e);
                            continue;
                        }
                    }
                }
                _ = &mut rx => {
                    info!("target_local_server_handler(tcp) received shutdown signal, exiting...");
                    return Ok(());
                }
            }
        }
    });

    async fn proxy_fn(stream: Box<dyn ChainedStream>) -> anyhow::Result<()> {
        let (mut read_half, mut write_half) = split(stream);

        let chunk = "hello";
        let mut buf = vec![0; 5];

        info!("proxy_fn(tcp) start write");

        for i in 0..100 {
            write_half
                .write_all(chunk.as_bytes())
                .await
                .inspect_err(|x| {
                    tracing::error!(
                        "proxy_fn(tcp) write error at iteration {}: {x:?}",
                        i
                    );
                })?;
        }
        write_half.flush().await?;

        info!("proxy_fn start(tcp) read");

        for i in 0..100 {
            read_half.read_exact(&mut buf).await.inspect_err(|x| {
                tracing::error!(
                    "proxy_fn(tcp) read error at iteration {}: {x:?}",
                    i
                );
            })?;
            assert_eq!(buf, "world".as_bytes().to_owned());
        }

        info!("proxy_fn(tcp) end");

        Ok(())
    }

    let proxy_task = tokio::spawn(async move {
        // give some time for the target local server to start
        tokio::time::sleep(Duration::from_secs(3)).await;

        let mut first_error: Option<anyhow::Error> = None;

        for destination in &destination_list {
            tracing::trace!("Attempting TCP connection(tcp) to: {}", destination);

            let dst: SocksAddr = match (destination.clone(), port).try_into() {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::error!(
                        "Failed to parse destination address(tcp): {}",
                        e
                    );
                    continue;
                }
            };

            let sess = Session {
                destination: dst.clone(),
                ..Default::default()
            };

            let stream = match tokio::time::timeout(
                Duration::from_secs(3),
                handler.connect_stream(&sess, resolver.clone()),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    tracing::info!("Successfully connected(tcp) to: {:?}", dst);
                    stream
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        "Failed to proxy connection(tcp) to {:?}: {}",
                        dst,
                        e
                    );
                    if first_error.is_none() {
                        first_error = Some(e.into());
                    }
                    continue;
                }
                Err(_) => {
                    tracing::error!(
                        "connect_stream timeout (5s) for destination(tcp): {}",
                        destination
                    );
                    continue;
                }
            };

            match tokio::time::timeout(Duration::from_secs(3), proxy_fn(stream))
                .await
            {
                Ok(Ok(())) => {
                    tracing::info!(
                        "proxy_fn succeeded for destination(tcp): {}",
                        destination
                    );
                    return Ok(());
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        "proxy_fn failed for destination(tcp) {}: {}",
                        destination,
                        e
                    );
                    continue;
                }
                Err(_) => {
                    tracing::error!(
                        "proxy_fn timeout (3s) for destination(tcp): {}",
                        destination
                    );
                    continue;
                }
            }
        }

        // Return the first connection error if available, otherwise return generic
        // error
        if let Some(err) = first_error {
            Err(err)
        } else {
            Err(anyhow!(
                "all destination test error(tcp): [{:?}]",
                destination_list
            ))
        }
    });

    let futs = vec![proxy_task, target_local_server_handler];

    let res = select_all(futs).await.0?;
    tx.send(()).ok(); // signal the target local server to shutdown
    res
}

pub async fn ping_pong_udp_test(
    handler: Arc<dyn OutboundHandler>,
    gateway_ip: Option<String>,
    port: u16,
) -> anyhow::Result<()> {
    // PATH: our proxy handler -> proxy-server(container) -> target local
    // server(127.0.0.1:port)

    let destination_list = destination_list(gateway_ip);

    let resolver = config_helper::build_dns_resolver().await?;

    let listener = UdpSocket::bind(format!("0.0.0.0:{}", port).as_str()).await?;
    info!("target local server started at: {}", listener.local_addr()?);

    async fn destination_fn(
        mut rx: tokio::sync::oneshot::Receiver<()>,
        listener: UdpSocket,
    ) -> anyhow::Result<()> {
        // Use inbound_stream here
        let chunk = "world";
        let mut buf = vec![0; 5];

        info!(
            "destination_fn(udp) waiting for data on {}",
            listener.local_addr()?
        );
        tracing::trace!("destination_fn start read");

        loop {
            tokio::select! {
                data = listener.recv_from(&mut buf) => {
                    match data {
                        Ok((len, src) ) => {
                            info!(
                                "destination_fn(udp) received {} bytes from {}: {:?}",
                                len,
                                src,
                                &buf[..len]
                            );
                            assert_eq!(&buf, b"hello");
                            info!("destination_fn(udp) sending response to {}", src);
                            tracing::trace!("destination_fn start write");
                            let sent = listener.send_to(chunk.as_bytes(), src).await?;
                            info!("destination_fn(udp) sent {} bytes", sent);
                            tracing::trace!("destination_fn end");
                        },
                        Err(e) => {
                            info!("Error accepting connection(tcp): {}", e);
                            continue;
                        }
                    }
                }
                _ = &mut rx => {
                    info!("target_local_server_handler(tcp) received shutdown signal, exiting...");
                    return Ok(());
                }
            }
        }
    }
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let target_local_server_handler: tokio::task::JoinHandle<
        Result<(), anyhow::Error>,
    > = tokio::spawn(async move { destination_fn(rx, listener).await });

    async fn proxy_fn(
        mut datagram: BoxedChainedDatagram,
        src_addr: SocksAddr,
        dst_addr: SocksAddr,
    ) -> anyhow::Result<()> {
        // let (mut sink, mut stream) = datagram.split();
        let packet =
            UdpPacket::new(b"hello".to_vec(), src_addr.clone(), dst_addr.clone());

        info!(
            "proxy_fn(udp) sending packet: src={:?}, dst={:?}, data={:?}",
            src_addr, dst_addr, b"hello"
        );
        trace!("proxy_fn(udp) start write");

        datagram.send(packet.clone()).await.map_err(|x| {
            tracing::error!("proxy_fn(udp) write error: {}", x);
            anyhow::Error::new(x)
        })?;

        info!("proxy_fn(udp) packet sent successfully, waiting for response...");
        trace!("proxy_fn(udp) start read");

        let pkt =
            tokio::time::timeout(Duration::from_secs(5), datagram.next()).await;

        match pkt {
            Ok(Some(pkt)) => {
                tracing::info!(
                    "proxy_fn(udp) received response: {} bytes, data={:?}",
                    pkt.data.len(),
                    pkt.data
                );
                assert_eq!(pkt.data, b"world");
                tracing::trace!("proxy_fn(udp) end");
                Ok(())
            }
            Ok(None) => {
                tracing::error!(
                    "proxy_fn(udp) datagram stream closed without response"
                );
                Err(anyhow!("datagram stream closed"))
            }
            Err(_) => {
                tracing::error!("proxy_fn(udp) timeout waiting for response (5s)");
                Err(anyhow!("timeout waiting for UDP response"))
            }
        }
    }

    let proxy_task = tokio::spawn(async move {
        // give some time for the target local server to start
        tokio::time::sleep(Duration::from_secs(3)).await;

        for destination in &destination_list {
            let src = ("127.0.0.1".to_owned(), 10005)
                .try_into()
                .expect("Failed to parse source address");

            let dst: SocksAddr = match (destination.clone(), port).try_into() {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::error!("Failed to parse destination address: {}", e);
                    continue;
                }
            };

            let sess = Session {
                destination: dst.clone(),
                ..Default::default()
            };

            let datagram =
                match handler.connect_datagram(&sess, resolver.clone()).await {
                    Ok(datagram) => datagram,
                    Err(e) => {
                        tracing::error!("Failed to proxy connection(udp): {}", e);
                        continue;
                    }
                };

            match tokio::time::timeout(
                Duration::from_secs(3),
                proxy_fn(datagram, src, dst),
            )
            .await
            {
                Ok(Ok(())) => {
                    tracing::info!(
                        "proxy_fn(udp) succeeded for destination: {}",
                        destination
                    );
                    return Ok(());
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        "proxy_fn(udp) failed for destination {}: {}",
                        destination,
                        e
                    );
                    continue;
                }
                Err(_) => {
                    tracing::error!(
                        "proxy_fn(udp) timeout (3s) for destination: {}",
                        destination
                    );
                    continue;
                }
            }
        }
        Err(anyhow!(
            "all destination test error(udp): [{:?}]",
            destination_list
        ))
    });

    let futs = vec![proxy_task, target_local_server_handler];
    let res = select_all(futs).await.0?;
    tx.send(()).ok();
    res
}

// latency test of the proxy, will reuse the `url_test` ability
pub async fn latency_test(
    handler: Arc<dyn OutboundHandler>,
) -> anyhow::Result<(Duration, Duration)> {
    let resolver = config_helper::build_dns_resolver().await?;
    let proxy_manager = ProxyManager::new(resolver.clone(), None);

    for attempt in 1..=3 {
        match proxy_manager
            .url_test(
                handler.clone(),
                "https://google.com",
                Some(Duration::from_secs(10)),
            )
            .await
        {
            Ok(latency) => return Ok(latency),
            Err(_) if attempt < 3 => {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!()
}

pub async fn dns_test(handler: Arc<dyn OutboundHandler>) -> anyhow::Result<()> {
    let src = SocksAddr::Ip(
        "127.0.0.1:0"
            .parse()
            .expect("Failed to parse source address"),
    );
    let dst = SocksAddr::Ip(
        "1.0.0.1:53"
            .parse()
            .expect("Failed to parse destination address"),
    );

    let sess = Session {
        destination: dst.clone(),
        ..Default::default()
    };

    let resolver = config_helper::build_dns_resolver().await?;
    let stream = handler.connect_datagram(&sess, resolver).await?;
    let (mut sink, mut stream) = stream.split();

    // DNS request for www.google.com A record
    let dns_req = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";
    let udp_packet = UdpPacket::new(dns_req.to_vec(), src, dst);

    let start_time = Instant::now();

    for _ in 0..3 {
        sink.send(udp_packet.clone()).await?;

        if let Some(pkt) = stream.next().await {
            assert!(!pkt.data.is_empty());
            tracing::debug!("dns test time cost: {:?}", start_time.elapsed());
            return Ok(());
        }
    }

    bail!("Failed to receive DNS response after 3 attempts")
}

#[derive(Clone, Copy)]
pub enum Suite {
    PingPongTcp,
    PingPongUdp,
    LatencyTcp,
    DnsUdp,
}

impl Suite {
    pub const fn all() -> &'static [Suite] {
        &[
            Suite::PingPongTcp,
            Suite::PingPongUdp,
            Suite::LatencyTcp,
            Suite::DnsUdp,
        ]
    }

    // some outbound handlers doesn't support udp
    #[allow(dead_code)]
    pub const fn tcp_tests() -> &'static [Suite] {
        &[Suite::PingPongTcp, Suite::LatencyTcp]
    }
}

// ── SOCKS5 / process-level e2e helpers (docker_test only) ────────────────────

/// Connect to a SOCKS5 proxy at `proxy_addr` and issue a CONNECT to
/// `target_host:target_port`.  Returns a `TcpStream` ready for data.
#[cfg(all(docker_test, throughput_test))]
#[allow(dead_code)]
async fn socks5_connect(
    proxy_addr: std::net::SocketAddr,
    target_host: &str,
    target_port: u16,
) -> std::io::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;
    // Greeting: VER=5, NMETHODS=1, METHOD=NO_AUTH(0)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(std::io::Error::other("SOCKS5 auth negotiation failed"));
    }
    // CONNECT request: VER=5, CMD=CONNECT(1), RSV=0, ATYP=DOMAIN(3)
    let host_bytes = target_host.as_bytes();
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;
    // Response header: VER, REP, RSV, ATYP
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 CONNECT failed: REP={}",
            hdr[1]
        )));
    }
    // Skip bound address
    match hdr[3] {
        0x01 => {
            let mut _skip = [0u8; 6];
            stream.read_exact(&mut _skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut _skip = [0u8; 18];
            stream.read_exact(&mut _skip).await?;
        }
        _ => {}
    }
    Ok(stream)
}

/// Wait until a TCP port accepts connections, or until `timeout_secs` elapses.
#[cfg(all(docker_test, throughput_test))]
#[allow(dead_code)]
async fn wait_for_port(port: u16, timeout_secs: u64) -> anyhow::Result<()> {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("port {} not ready after {}s", port, timeout_secs);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Start clash-rs as a subprocess with `config_yaml`, then run a full-stack
/// upload+download throughput test through its SOCKS5 inbound.
///
/// The echo server is bound locally on `echo_port`; the SOCKS5 CONNECT target
/// is resolved using `destination_list(gateway_ip)` so docker containers can
/// reach back to the host.
///
/// `payload_bytes` is transferred in each direction (upload then download).
/// Results are logged with `tracing::info!` and — when
/// `THROUGHPUT_RESULTS_FILE` is set — appended as a JSON line to that file for
/// CI collection.
#[cfg(all(docker_test, throughput_test))]
pub async fn clash_process_e2e_throughput(
    binary: &std::path::Path,
    config_yaml: &str,
    label: &str,
    socks_port: u16,
    echo_port: u16,
    gateway_ip: Option<String>,
    payload_bytes: usize,
) -> anyhow::Result<ThroughputResult> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Each clash-rs instance gets its own temp directory so that concurrent
    // runs never share the same `cache.db` or other working-dir files.
    let work_dir = tempfile::TempDir::new()?;

    // Write config inside the per-instance work dir so the path stays valid
    // for the duration of the clash-rs process.
    let cfg_path = work_dir.path().join("config.yaml");
    std::fs::write(&cfg_path, config_yaml.as_bytes())?;

    // --- spawn clash-rs subprocess ---
    // Log to a per-instance file so output from concurrent runs never interleave
    // or get lost in pipe buffering.
    let log_path = work_dir.path().join("clash-rs.log");
    let log_file = std::fs::File::create(&log_path)?;
    let log_file2 = log_file.try_clone()?;
    let mut child = tokio::process::Command::new(binary)
        .arg("-c")
        .arg(&cfg_path)
        .current_dir(work_dir.path())
        .kill_on_drop(true)
        .stdout(log_file)
        .stderr(log_file2)
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn clash-rs: {e}"))?;

    // --- start echo server on echo_port ---
    let echo_listener =
        tokio::net::TcpListener::bind(format!("0.0.0.0:{}", echo_port)).await?;
    let payload_bytes_echo = payload_bytes;
    let echo_task = tokio::spawn(async move {
        // Accept one connection
        let (mut stream, _) = echo_listener.accept().await?;
        let chunk_size = 64 * 1024_usize;
        let mut buf = vec![0u8; chunk_size];
        // Phase 1: receive payload_bytes
        let mut received = 0usize;
        while received < payload_bytes_echo {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                anyhow::bail!("echo server: premature EOF on receive");
            }
            received += n;
        }
        // Phase 2: send payload_bytes back
        let data = vec![0x42u8; chunk_size];
        let mut sent = 0usize;
        while sent < payload_bytes_echo {
            let to_send = chunk_size.min(payload_bytes_echo - sent);
            stream.write_all(&data[..to_send]).await?;
            sent += to_send;
        }
        stream.flush().await?;
        anyhow::Ok(())
    });

    // --- wait for SOCKS5 inbound to be ready ---
    // First, give the process a moment and check it hasn't crashed immediately.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    if let Ok(Some(status)) = child.try_wait() {
        let log_content = std::fs::read_to_string(&log_path).unwrap_or_default();
        anyhow::bail!(
            "clash-rs [{label}] exited immediately with status: {:?}\n--- log \
             ---\n{}",
            status,
            log_content
        );
    }
    wait_for_port(socks_port, 60).await.map_err(|e| {
        child.start_kill().ok();
        let log_content = std::fs::read_to_string(&log_path).unwrap_or_default();
        eprintln!(
            "--- clash-rs [{label}] log (port not ready) ---\n{}",
            log_content
        );
        e
    })?;

    // --- find a target address reachable from docker ---
    let destinations = destination_list(gateway_ip);
    let mut last_err = anyhow::anyhow!("no destinations");

    'dest: for dest in &destinations {
        let proxy_addr: std::net::SocketAddr =
            format!("127.0.0.1:{}", socks_port).parse().unwrap();

        let mut conn = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            socks5_connect(proxy_addr, dest, echo_port),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                last_err = e.into();
                continue 'dest;
            }
            Err(_) => {
                last_err = anyhow::anyhow!("socks5_connect timeout");
                continue 'dest;
            }
        };

        let chunk_size = 64 * 1024_usize;
        let upload_data = vec![0x42u8; chunk_size];
        let mut read_buf = vec![0u8; chunk_size];

        // Upload — any error means this destination is unusable; try the next
        let upload_start = std::time::Instant::now();
        let mut sent = 0usize;
        let mut transfer_ok = true;
        while sent < payload_bytes {
            let to_send = chunk_size.min(payload_bytes - sent);
            match conn.write_all(&upload_data[..to_send]).await {
                Ok(()) => sent += to_send,
                Err(e) => {
                    last_err = e.into();
                    transfer_ok = false;
                    break;
                }
            }
        }
        if !transfer_ok {
            continue 'dest;
        }
        if let Err(e) = conn.flush().await {
            last_err = e.into();
            continue 'dest;
        }
        let upload_elapsed = upload_start.elapsed();

        // Download
        let download_start = std::time::Instant::now();
        let mut received = 0usize;
        while received < payload_bytes {
            match conn.read(&mut read_buf).await {
                Ok(0) => {
                    last_err = anyhow::anyhow!("premature EOF on download");
                    transfer_ok = false;
                    break;
                }
                Ok(n) => received += n,
                Err(e) => {
                    last_err = e.into();
                    transfer_ok = false;
                    break;
                }
            }
        }
        if !transfer_ok {
            continue 'dest;
        }
        let download_elapsed = download_start.elapsed();

        let mb = payload_bytes as f64 / 1024.0 / 1024.0;
        let upload_mbps = mb * 8.0 / upload_elapsed.as_secs_f64();
        let download_mbps = mb * 8.0 / download_elapsed.as_secs_f64();

        tracing::info!(
            "e2e throughput [{}] ({} MB): upload={:.1} Mbps  download={:.1} Mbps",
            label,
            payload_bytes / 1024 / 1024,
            upload_mbps,
            download_mbps,
        );

        echo_task.await??;
        child.start_kill().ok();
        let result = ThroughputResult {
            label: label.to_owned(),
            upload_mbps,
            download_mbps,
            total_bytes: payload_bytes,
        };
        write_throughput_result(&result);
        return Ok(result);
    }

    echo_task.abort();
    child.start_kill().ok();
    Err(last_err)
}

// ─────────────────────────────────────────────────────────────────────────────

pub async fn run_test_suites_and_cleanup(
    handler: Arc<dyn OutboundHandler>,
    docker_test_runner: impl RunAndCleanup,
    suites: &[Suite],
) -> anyhow::Result<()> {
    let suites = suites.to_owned();
    let gateway_ip = docker_test_runner.docker_gateway_ip();
    docker_test_runner
        .run_and_cleanup(async move {
            for suite in suites {
                match suite {
                    Suite::PingPongTcp => {
                        let rv = ping_pong_test(
                            handler.clone(),
                            gateway_ip.clone(),
                            10001,
                        )
                        .await;
                        if rv.is_err() {
                            tracing::error!("ping_pong_test failed: {:?}", rv);
                            return rv;
                        } else {
                            tracing::info!("ping_pong_test success");
                        }
                    }
                    Suite::PingPongUdp => {
                        let rv = ping_pong_udp_test(
                            handler.clone(),
                            gateway_ip.clone(),
                            10001,
                        )
                        .await;
                        if rv.is_err() {
                            tracing::error!("ping_pong_udp_test failed: {:?}", rv);
                            return rv;
                        } else {
                            tracing::info!("ping_pong_udp_test success");
                        }
                    }
                    Suite::LatencyTcp => {
                        let rv = latency_test(handler.clone()).await;
                        match rv {
                            Ok(_) => {
                                tracing::info!("url test success: ",);
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Suite::DnsUdp => {
                        let rv = dns_test(handler.clone()).await;
                        if let Err(rv) = rv {
                            return Err(rv);
                        } else {
                            tracing::info!("dns_test success");
                        }
                    }
                }
            }

            Ok(())
        })
        .await
}
