use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    app::dispatcher::ChainedStream,
    proxy::OutboundHandler,
    session::{Session, SocksAddr},
};
use futures::{future::select_all, Future};
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};
use tracing::info;

use self::docker_runner::{MultiDockerTestRunner, DockerTest, DockerTestRunner};

pub mod config_helper;
pub mod consts;
pub mod docker_runner;

// TODO: add the throughput metrics
pub async fn ping_pong_test(handler: Arc<dyn OutboundHandler>, port: u16) -> anyhow::Result<()> {
    // PATH: our proxy handler -> proxy-server(container) -> target local server(127.0.0.1:port)

    let sess = Session {
        destination: ("127.0.0.1".to_owned(), port)
            .try_into()
            .unwrap_or_else(|_| panic!("")),
        ..Default::default()
    };

    let (_, resolver) = config_helper::load_config().await?;

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

            tracing::info!("Accepted connection from: {}", stream.peer_addr().unwrap());
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
                    tracing::error!("proxy_fn write error: {}", x);
                })?;
        }
        write_half.flush().await?;

        tracing::info!("proxy_fn start read");

        for _ in 0..100 {
            read_half.read_exact(&mut buf).await.inspect_err(|x| {
                tracing::error!("proxy_fn read error: {}", x);
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

/// Represents the options for a latency test.
pub struct LatencyTestOption<'a> {
    /// The destination address for the test.
    pub dst: SocksAddr,
    /// The request data for the test.
    pub req: &'a [u8],
    /// The expected response data for the test.
    pub expected_resp: &'a [u8],
    /// Indicates whether to read the exact amount of data specified by `expected_resp`.
    pub read_exact: bool,
}

// latency test of the proxy
pub async fn latency_test(
    handler: Arc<dyn OutboundHandler>,
    option: LatencyTestOption<'_>,
) -> anyhow::Result<Duration> {
    // our proxy handler -> proxy-server -> destination(google.com)

    let sess = Session {
        destination: option.dst,
        ..Default::default()
    };

    let (_, resolver) = config_helper::load_config().await?;

    let stream = handler.connect_stream(&sess, resolver).await?;

    let (mut read_half, mut write_half) = split(stream);

    write_half.write_all(option.req).await?;
    write_half.flush().await?;
    drop(write_half);

    let start_time = Instant::now();
    let mut response = vec![0; option.expected_resp.len()];

    if option.read_exact {
        read_half.read_exact(&mut response).await?;
        tracing::debug!("response:\n{}", String::from_utf8_lossy(&response));
        assert_eq!(&response, option.expected_resp);
    } else {
        read_half.read_to_end(&mut response).await?;
        tracing::debug!("response:\n{}", String::from_utf8_lossy(&response));
        assert_eq!(&response, option.expected_resp);
    }

    let end_time = Instant::now();
    tracing::debug!("time cost:{:?}", end_time.duration_since(start_time));
    Ok(end_time.duration_since(start_time))
}

pub async fn run(
    handler: Arc<dyn OutboundHandler>,
    runner_creater: impl Future<Output = anyhow::Result<DockerTestRunner>>,
) -> anyhow::Result<()> {
    let watch = match runner_creater.await {
        Ok(runner) => runner,
        Err(e) => {
            tracing::warn!("cannot start container, please check the docker environment");
            return Err(e);
        }
    };
    run_inner(handler, watch).await
}

pub async fn run_chained(
    handler: Arc<dyn OutboundHandler>,
    chained: MultiDockerTestRunner,
) -> anyhow::Result<()> {
    run_inner(handler, chained).await
}

pub async fn run_inner(
    handler: Arc<dyn OutboundHandler>,
    watch: impl DockerTest,
) -> anyhow::Result<()> {
    watch
        .run_and_cleanup(async move {
            let rv = ping_pong_test(handler.clone(), 10001).await;
            if rv.is_err() {
                tracing::error!("ping_pong_test failed: {:?}", rv);
                return rv;
            } else {
                tracing::info!("ping_pong_test success");
            }

            let rv = latency_test(
                handler,
                LatencyTestOption {
                    dst: SocksAddr::Domain("example.com".to_owned(), 80),
                    req: consts::EXAMPLE_REQ,
                    expected_resp: consts::EXAMLE_RESP_200,
                    read_exact: true,
                },
            )
            .await;
            if rv.is_err() {
                return Err(rv.unwrap_err());
            } else {
                tracing::info!("latency test success: {}", rv.unwrap().as_millis());
            }

            return Ok(());
        })
        .await
}
