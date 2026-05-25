use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DEFAULT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct TcpEchoConfig {
    pub response: &'static [u8],
    pub expected_request: Option<&'static [u8]>,
    pub read_size: usize,
    pub iterations: Option<usize>,
}

impl Default for TcpEchoConfig {
    fn default() -> Self {
        Self {
            response: b"world",
            expected_request: Some(b"hello"),
            read_size: 5,
            iterations: Some(10),
        }
    }
}

pub struct TcpEchoServer {
    handle: Option<tokio::task::JoinHandle<()>>,
    port: u16,
}

impl TcpEchoServer {
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with(TcpEchoConfig::default()).await
    }

    pub async fn start_with(config: TcpEchoConfig) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        let handle = tokio::spawn(async move {
            let stream = match tokio::time::timeout(
                DEFAULT_ACCEPT_TIMEOUT,
                listener.accept(),
            )
            .await
            {
                Ok(Ok((stream, _))) => stream,
                _ => return,
            };
            let (mut reader, mut writer) = stream.into_split();
            let mut buf = vec![0u8; config.read_size];

            match config.iterations {
                Some(n) => {
                    for _ in 0..n {
                        if reader.read_exact(&mut buf).await.is_err() {
                            break;
                        }
                        if let Some(expected) = config.expected_request {
                            assert_eq!(buf.as_slice(), expected);
                        }
                        if writer.write_all(config.response).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                }
                None => {
                    while reader.read_exact(&mut buf).await.is_ok() {
                        if let Some(expected) = config.expected_request {
                            assert_eq!(buf.as_slice(), expected);
                        }
                        if writer.write_all(config.response).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                }
            }
        });

        Ok(Self {
            handle: Some(handle),
            port,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for TcpEchoServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}
