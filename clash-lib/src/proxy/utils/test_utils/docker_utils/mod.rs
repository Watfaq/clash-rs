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
