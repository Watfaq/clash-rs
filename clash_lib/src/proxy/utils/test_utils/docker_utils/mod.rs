use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, ChainedStream},
        remote_content_manager::ProxyManager,
    },
    proxy::{datagram::UdpPacket, OutboundHandler},
    session::{Session, SocksAddr},
};
use futures::{future::select_all, SinkExt, StreamExt};
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tracing::info;

use self::docker_runner::RunAndCleanup;

pub mod config_helper;
pub mod consts;
pub mod docker_runner;

// TODO: add the throughput metrics
pub async fn ping_pong_test(
    handler: Arc<dyn OutboundHandler>,
    port: u16,
) -> anyhow::Result<()> {
    // PATH: our proxy handler -> proxy-server(container) -> target local
    // server(127.0.0.1:port)

    let sess = Session {
        destination: (
            if cfg!(any(target_os = "linux", target_os = "android")) {
                "127.0.0.1".to_owned()
            } else {
                "host.docker.internal".to_owned()
            },
            port,
        )
            .try_into()
            .unwrap_or_else(|_| panic!("")),
        ..Default::default()
    };

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

        tracing::info!("proxy_fn start write");

        for _ in 0..100 {
            write_half
                .write_all(chunk.as_bytes())
                .await
                .inspect_err(|x| {
                    tracing::error!("proxy_fn write error: {x:?}");
                })?;
        }
        write_half.flush().await?;

        tracing::info!("proxy_fn start read");

        for _ in 0..100 {
            read_half.read_exact(&mut buf).await.inspect_err(|x| {
                tracing::error!("proxy_fn read error: {x:?}");
            })?;
            assert_eq!(buf, "world".as_bytes().to_owned());
        }

        tracing::info!("proxy_fn end");

        Ok(())
    }

    let proxy_task = tokio::spawn(async move {
        // give some time for the target local server to start
        tokio::time::sleep(Duration::from_secs(3)).await;

        match handler.connect_stream(&sess, resolver).await {
            Ok(stream) => proxy_fn(stream).await,
            Err(e) => {
                tracing::error!("Failed to proxy connection: {}", e);
                Err(anyhow!("Failed to proxy connection: {}", e))
            }
        }
    });

    let futs = vec![proxy_task, target_local_server_handler];

    select_all(futs).await.0?
}

pub async fn ping_pong_udp_test(
    handler: Arc<dyn OutboundHandler>,
    port: u16,
) -> anyhow::Result<()> {
    // PATH: our proxy handler -> proxy-server(container) -> target local
    // server(127.0.0.1:port)

    let src = ("127.0.0.1".to_owned(), 10005)
        .try_into()
        .unwrap_or_else(|_| panic!(""));
    let dst: SocksAddr = (
        if cfg!(any(target_os = "linux", target_os = "android")) {
            "127.0.0.1".to_owned()
        } else {
            "host.docker.internal".to_owned()
        },
        port,
    )
        .try_into()
        .unwrap_or_else(|_| panic!(""));

    let sess = Session {
        destination: dst.clone(),
        ..Default::default()
    };

    let resolver = config_helper::build_dns_resolver().await?;

    let listener = UdpSocket::bind(format!("0.0.0.0:{}", port).as_str()).await?;
    info!("target local server started at: {}", listener.local_addr()?);

    async fn destination_fn(listener: UdpSocket) -> anyhow::Result<()> {
        // Use inbound_stream here
        let chunk = "world";
        let mut buf = vec![0; 5];

        tracing::trace!("destination_fn start read");

        let (_, src) = listener.recv_from(&mut buf).await?;
        assert_eq!(&buf, b"hello");

        tracing::trace!("destination_fn start write");

        listener.send_to(chunk.as_bytes(), src).await?;

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
        let packet = UdpPacket::new(b"hello".to_vec(), src_addr, dst_addr);

        tracing::trace!("proxy_fn start write");

        datagram.send(packet.clone()).await.map_err(|x| {
            tracing::error!("proxy_fn write error: {}", x);
            anyhow::Error::new(x)
        })?;

        tracing::trace!("proxy_fn start read");

        let pkt = datagram.next().await;
        let pkt = pkt.ok_or_else(|| anyhow!("no packet received"))?;
        assert_eq!(pkt.data, b"world");

        tracing::trace!("proxy_fn end");

        Ok(())
    }

    let proxy_task = tokio::spawn(async move {
        // give some time for the target local server to start
        tokio::time::sleep(Duration::from_secs(3)).await;

        match handler.connect_datagram(&sess, resolver).await {
            Ok(stream) => proxy_fn(stream, src, dst).await,
            Err(e) => {
                tracing::error!("Failed to proxy connection: {}", e);
                Err(anyhow!("Failed to proxy connection: {}", e))
            }
        }
    });

    let futs = vec![proxy_task, target_local_server_handler];

    select_all(futs).await.0?
}

// latency test of the proxy, will reuse the `url_test` ability
pub async fn latency_test(
    handler: Arc<dyn OutboundHandler>,
) -> anyhow::Result<(u16, u16)> {
    let resolver = config_helper::build_dns_resolver().await?;
    let proxy_manager = ProxyManager::new(resolver.clone());
    proxy_manager
        .url_test(handler, "https://example.com", None)
        .await
        .map_err(Into::into)
}

pub async fn dns_test(handler: Arc<dyn OutboundHandler>) -> anyhow::Result<()> {
    let src = SocksAddr::Ip("127.0.0.1:0".parse().unwrap());
    let dst = SocksAddr::Ip("1.0.0.1:53".parse().unwrap());

    let sess = Session {
        destination: dst.clone(),
        ..Default::default()
    };

    let resolver = config_helper::build_dns_resolver().await?;

    // we don't need the resolver, so it doesn't matter to create a casual one
    let stream = handler.connect_datagram(&sess, resolver).await?;

    let (mut sink, mut stream) = stream.split();

    // send dns request to domain
    let dns_req = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";
    let udp_packet: UdpPacket = UdpPacket::new(dns_req.to_vec(), src, dst);

    let start_time = Instant::now();
    let max_retry = 3;

    for _ in 0..max_retry {
        sink.send(udp_packet.clone()).await?;
        let pkt = stream.next().await;
        if pkt.is_none() {
            continue;
        }
        let pkt = pkt.unwrap();
        assert!(!pkt.data.is_empty());
        let end_time = Instant::now();
        tracing::debug!(
            "dns test time cost:{:?}",
            end_time.duration_since(start_time)
        );
        return Ok(());
    }
    bail!("fail to receive dns response");
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
    docker_test_runner
        .run_and_cleanup(async move {
            for suite in suites {
                match suite {
                    Suite::PingPongTcp => {
                        let rv = ping_pong_test(handler.clone(), 10001).await;
                        if rv.is_err() {
                            tracing::error!("ping_pong_test failed: {:?}", rv);
                            return rv;
                        } else {
                            tracing::info!("ping_pong_test success");
                        }
                    }
                    Suite::PingPongUdp => {
                        let rv = ping_pong_udp_test(handler.clone(), 10001).await;
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
