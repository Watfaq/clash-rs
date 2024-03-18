use std::sync::Arc;

use crate::{
    app::dispatcher::ChainedStream,
    proxy::OutboundHandler,
    session::{Session, SocksAddr},
};
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    join,
    net::TcpListener,
};
use tracing::{debug, error};

pub mod config_helper;
pub mod consts;
pub mod docker_runner;

// TODO: add the thoroughput metrics
pub async fn benchmark_proxy(handler: Arc<dyn OutboundHandler>, port: u16) -> anyhow::Result<()> {
    // proxy -> proxy-server -> destination(127.0.0.1:port)

    // the destination is a local server
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
            Ok((stream, _)) => match destination_fn(stream).await {
                Ok(_) => {}
                Err(e) => eprintln!("Failed to serve: {}", e),
            },
            Err(e) => {
                // Handle error e, log it, or ignore it
                eprintln!("Failed to accept connection: {}", e);
            }
        }
        debug!("server task finished");
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
            Ok(stream) => match proxy_fn(stream).await {
                Ok(_) => {}
                Err(e) => error!("Failed to to proxy: {}", e),
            },
            Err(e) => error!("Failed to accept connection: {}", e),
        }
        debug!("proxy task finished");
    });

    let _ = join!(proxy_task, target_local_server_handler);

    Ok(())
}

pub struct LatencyTestOption<'a> {
    pub dst: SocksAddr,
    pub req: &'a [u8],
    pub expected_resp: &'a [u8],
    pub read_exact: bool,
}

pub async fn latency_test_proxy(
    handler: Arc<dyn OutboundHandler>,
    option: LatencyTestOption<'_>,
) -> anyhow::Result<()> {
    // proxy -> proxy-server -> destination(google.com)

    // the destination is a local server
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
