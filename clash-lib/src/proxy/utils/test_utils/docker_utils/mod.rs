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
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split},
    net::{TcpListener, UdpSocket},
};
use tracing::info;

pub mod config_helper;
pub mod consts;
pub mod docker_runner;

// TODO: add the throughput metrics
pub async fn ping_pong_test(
    handler: Arc<dyn OutboundHandler>,
    gateway_ip: Option<String>,
    port: u16,
) -> anyhow::Result<()> {
    // PATH: our proxy handler -> proxy-server(container) -> target local
    // server(127.0.0.1:port)

    let mut destination_list = vec![
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "127.0.0.1".to_owned(),
        "host.docker.internal".to_owned(),
    ];
    if let Some(ip) = option_env!("CLIENT_IP") {
        destination_list.insert(0, ip.to_owned());
    }
    if let Some(ip) = gateway_ip {
        destination_list.push(ip);
    }

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

        tracing::info!("destination_fn start read");

        for _ in 0..100 {
            read_half.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"hello");
        }

        tracing::info!("destination_fn start write");

        for _ in 0..100 {
            write_half.write_all(chunk.as_bytes()).await?;
            write_half.flush().await?;
        }

        tracing::info!("destination_fn end");
        Ok(())
    }

    let target_local_server_handler = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await?;

            tracing::info!(
                "Accepted connection from: {}",
                stream.peer_addr().unwrap()
            );
            destination_fn(stream).await?
        }
    });

    async fn proxy_fn(stream: Box<dyn ChainedStream>) -> anyhow::Result<()> {
        let (mut read_half, mut write_half) = split(stream);

        let chunk = "hello";
        let mut buf = vec![0; 5];

        tracing::info!("proxy_fn(tcp) start write");

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

        tracing::info!("proxy_fn start read");

        for i in 0..100 {
            read_half.read_exact(&mut buf).await.inspect_err(|x| {
                tracing::error!(
                    "proxy_fn(tcp) read error at iteration {}: {x:?}",
                    i
                );
            })?;
            assert_eq!(buf, "world".as_bytes().to_owned());
        }

        tracing::info!("proxy_fn(tcp) end");

        Ok(())
    }

    let proxy_task = tokio::spawn(async move {
        // give some time for the target local server to start
        tokio::time::sleep(Duration::from_secs(3)).await;

        let mut first_error: Option<anyhow::Error> = None;

        for destination in &destination_list {
            tracing::trace!("Attempting TCP connection to: {}", destination);

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

            let stream = match tokio::time::timeout(
                Duration::from_secs(5),
                handler.connect_stream(&sess, resolver.clone()),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    tracing::info!("Successfully connected to: {:?}", dst);
                    stream
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        "Failed to proxy connection to {:?}: {}",
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
                        "connect_stream timeout (5s) for destination: {}",
                        destination
                    );
                    continue;
                }
            };

            if let Ok(()) = proxy_fn(stream).await {
                return Ok(());
            }
        }

        // Return the first connection error if available, otherwise return generic
        // error
        if let Some(err) = first_error {
            Err(err)
        } else {
            Err(anyhow!(
                "all destination test error: [{:?}]",
                destination_list
            ))
        }
    });

    let futs = vec![proxy_task, target_local_server_handler];

    select_all(futs).await.0?
}

pub async fn ping_pong_udp_test(
    handler: Arc<dyn OutboundHandler>,
    gateway_ip: Option<String>,
    port: u16,
) -> anyhow::Result<()> {
    // PATH: our proxy handler -> proxy-server(container) -> target local
    // server(127.0.0.1:port)

    let mut destination_list = vec![
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "127.0.0.1".to_owned(),
        "host.docker.internal".to_owned(),
    ];
    if let Some(ip) = option_env!("CLIENT_IP") {
        destination_list.insert(0, ip.to_owned());
    }
    if let Some(ip) = gateway_ip {
        destination_list.push(ip);
    }

    let resolver = config_helper::build_dns_resolver().await?;

    let listener = UdpSocket::bind(format!("0.0.0.0:{}", port).as_str()).await?;
    info!("target local server started at: {}", listener.local_addr()?);

    async fn destination_fn(listener: UdpSocket) -> anyhow::Result<()> {
        // Use inbound_stream here
        let chunk = "world";
        let mut buf = vec![0; 5];

        tracing::info!(
            "destination_fn(udp) waiting for data on {}",
            listener.local_addr()?
        );
        tracing::trace!("destination_fn start read");

        let (len, src) = listener.recv_from(&mut buf).await?;
        tracing::info!(
            "destination_fn(udp) received {} bytes from {}: {:?}",
            len,
            src,
            &buf[..len]
        );
        assert_eq!(&buf, b"hello");

        tracing::info!("destination_fn(udp) sending response to {}", src);
        tracing::trace!("destination_fn start write");

        let sent = listener.send_to(chunk.as_bytes(), src).await?;
        tracing::info!("destination_fn(udp) sent {} bytes", sent);

        tracing::trace!("destination_fn end");
        Ok(())
    }

    let target_local_server_handler: tokio::task::JoinHandle<
        Result<(), anyhow::Error>,
    > = tokio::spawn(async move { destination_fn(listener).await });

    async fn proxy_fn(
        mut datagram: BoxedChainedDatagram,
        src_addr: SocksAddr,
        dst_addr: SocksAddr,
    ) -> anyhow::Result<()> {
        // let (mut sink, mut stream) = datagram.split();
        let packet =
            UdpPacket::new(b"hello".to_vec(), src_addr.clone(), dst_addr.clone());

        tracing::info!(
            "proxy_fn(udp) sending packet: src={:?}, dst={:?}, data={:?}",
            src_addr,
            dst_addr,
            b"hello"
        );
        tracing::trace!("proxy_fn(udp) start write");

        datagram.send(packet.clone()).await.map_err(|x| {
            tracing::error!("proxy_fn(udp) write error: {}", x);
            anyhow::Error::new(x)
        })?;

        tracing::info!(
            "proxy_fn(udp) packet sent successfully, waiting for response..."
        );
        tracing::trace!("proxy_fn(udp) start read");

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

            if let Ok(()) = proxy_fn(datagram, src, dst).await {
                return Ok(());
            }
        }
        Err(anyhow!(
            "all destination test error(udp): [{:?}]",
            destination_list
        ))
    });

    let futs = vec![proxy_task, target_local_server_handler];

    select_all(futs).await.0?
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
