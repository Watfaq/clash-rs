use std::sync::Arc;

use crate::{
    app::dispatcher::ChainedStream,
    proxy::OutboundHandler,
    session::{Session, SocksAddr},
};
use futures::future::join_all;
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};
use tracing::{debug, error};

pub mod config_helper;
pub mod consts;
pub mod docker_runner;

// TODO: add the thoroughput metrics
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

    async fn destination_fn<T>(incoming: T) -> anyhow::Result<()>
    where
        T: AsyncRead + AsyncWrite,
    {
        // Use inbound_stream here
        let (mut read_half, mut write_half) = split(incoming);
        let chunk = "world";
        let mut buf = vec![0; 5];

        for _ in 0..100 {
            read_half.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"hello");
        }

        for _ in 0..100 {
            write_half.write_all(chunk.as_bytes()).await?;
            write_half.flush().await?;
        }
        Ok(())
    }

    let target_local_server_handler = tokio::spawn(async move {
        match listener.accept().await {
            Ok((stream, _)) => destination_fn(stream).await,
            Err(e) => {
                // Handle error e, log it, or ignore it
                error!("Failed to accept connection: {}", e);
                Err(anyhow!("Failed to accept connection: {}", e))
            }
        }
    });

    async fn proxy_fn(stream: Box<dyn ChainedStream>) -> anyhow::Result<()> {
        let (mut read_half, mut write_half) = split(stream);

        let chunk = "hello";
        let mut buf = vec![0; 5];

        for _ in 0..100 {
            write_half.write_all(chunk.as_bytes()).await?;
        }
        write_half.flush().await?;
        drop(write_half);

        for _ in 0..100 {
            read_half.read_exact(&mut buf).await?;
            assert_eq!(buf, "world".as_bytes().to_owned());
        }
        drop(read_half);
        Ok(())
    }

    let proxy_task = tokio::spawn(async move {
        match handler.connect_stream(&sess, resolver).await {
            Ok(stream) => proxy_fn(stream).await,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                Err(anyhow!("Failed to accept connection: {}", e))
            }
        }
    });

    let futs = vec![proxy_task, target_local_server_handler];

    match join_all(futs)
        .await
        .into_iter()
        .filter_map(|x| x.err())
        .next()
    {
        Some(e) => Err(anyhow!("Failed to run ping_pong_test: {}", e)),
        None => Ok(()),
    }
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
) -> anyhow::Result<()> {
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

    let start_time = std::time::SystemTime::now();
    let mut response = vec![0; option.expected_resp.len()];

    if option.read_exact {
        read_half.read_exact(&mut response).await?;
        debug!("response:\n{}", String::from_utf8_lossy(&response));
        assert_eq!(&response, option.expected_resp);
    } else {
        read_half.read_to_end(&mut response).await?;
        debug!("response:\n{}", String::from_utf8_lossy(&response));
        assert_eq!(&response, option.expected_resp);
    }

    let end_time = std::time::SystemTime::now();
    debug!(
        "time cost:{:?}",
        end_time.duration_since(start_time).unwrap()
    );
    Ok(())
}
