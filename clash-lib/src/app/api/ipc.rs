use tracing::error;

#[cfg(windows)]
pub async fn serve_ipc(router: axum::Router, path: &str) -> crate::Result<()> {
    use hyper_util::rt::TokioIo;
    use tokio::net::windows::named_pipe;
    use tower::Service as _;
    use tracing::info;
    info!("Starting API server on NamedPipe {path}");

    let server = named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(path)
        .map_err(|e| crate::Error::Operation(format!("Cannot create pipe {e}")))?;

    let mut server = server;
    loop {
        server
            .connect()
            .await
            .map_err(|e| crate::Error::Operation(format!("NamedPipe error: {e}")))?;
        let connected_client = server;
        server = named_pipe::ServerOptions::new().create(path).map_err(|e| {
            crate::Error::Operation(format!("Cannot create NamedPipe: {e}"))
        })?;
        let router = router.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(connected_client);
            let hyper_service = hyper::service::service_fn(move |request: _| {
                router.clone().call(request)
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, hyper_service)
                .await
            {
                error!("NamedPipe error: {}", e);
            }
        });
    }
}
#[cfg(unix)]
pub async fn serve_ipc(router: axum::Router, path: &str) -> crate::Result<()> {
    use std::path::PathBuf;
    use tracing::info;

    use axum::{extract::connect_info::Connected, serve::IncomingStream};
    use std::sync::Arc;
    use tokio::net::UnixListener;
    let path = PathBuf::from(path);
    let app_clone = router.clone();

    info!("Start API server on IPC address {:?}", path);

    if let Err(e) = tokio::fs::remove_file(&path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(crate::Error::Operation(format!(
            "Cannot remove existing IPC file: {e}",
        )));
    }

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            crate::Error::Operation(format!("Cannot create IPC dir: {e}"))
        })?;
    }

    let uds = tokio::net::UnixListener::bind(&path).map_err(|e| {
        crate::Error::Operation(format!("Cannot bind on IPC address: {e}"))
    })?;

    #[derive(Clone, Debug)]
    #[allow(dead_code)]
    struct UdsConnectInfo {
        peer_addr: Arc<tokio::net::unix::SocketAddr>,
        peer_cred: tokio::net::unix::UCred,
    }

    impl Connected<IncomingStream<'_, UnixListener>> for UdsConnectInfo {
        fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
            let peer_addr = stream.io().peer_addr().unwrap();
            let peer_cred = stream.io().peer_cred().unwrap();
            Self {
                peer_addr: Arc::new(peer_addr),
                peer_cred,
            }
        }
    }

    axum::serve(
        uds,
        app_clone.into_make_service_with_connect_info::<UdsConnectInfo>(),
    )
    .await
    .map_err(|e| {
        error!("IPC API Server error: {}", e);
        crate::Error::Operation(format!("IPC API Server error: {e}"))
    })
}

#[cfg(all(not(unix), not(windows)))]
pub async fn serve_ipc(router: axum::Router, path: &str) -> crate::Result<()> {
    error!("IPC only get supported on Unix and Windows");
    Err(crate::Error::Operation(
        "IPC only get supported on Unix and Windows".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use serde::{Deserialize, Serialize};
    use tracing_test::traced_test;

    fn test_router() -> Router {
        Router::new().route(
            "/test",
            get(|| async {
                Json(Response {
                    message: "Hello, World!".to_string(),
                })
            }),
        )
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct Response {
        message: String,
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(all(not(unix), not(windows)))]
    async fn test_serve_ipc_unsupported_platform() {
        let router = test_router();
        let result = serve_ipc(router, "test_path").await;
        assert!(result.is_err());
        assert!(logs_contain("IPC only get supported on Unix and Windows"));
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(windows)]
    async fn test_serve_ipc_windows_with_client() -> anyhow::Result<()> {
        use hyper::client::conn;
        use hyper_util::rt::TokioIo;
        use tokio::{
            net::windows::named_pipe::ClientOptions,
            time::{Duration, timeout},
        };

        let router = test_router();
        let path = r"\\.\pipe\test_named_pipe_win_client";

        let server_handle = tokio::spawn({
            let router = router.clone();
            async move {
                let _ = serve_ipc(router, path).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_result = timeout(Duration::from_secs(5), async {
            use anyhow::Context;
            use bytes::Bytes;
            use futures::StreamExt;
            use http_body_util::{BodyExt, Empty};

            let client = ClientOptions::new()
                .open(path)
                .context("Failed to connect to named pipe")?;

            let io = TokioIo::new(client);
            let (mut request_sender, connection) = conn::http1::handshake(io)
                .await
                .context("Failed to handshake")?;

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Connection error: {}", e);
                }
            });

            let request = hyper::Request::builder()
                .uri("http://localhost/test")
                .header("Host", "localhost")
                .body(Empty::<Bytes>::new())
                .context("Failed to build request")?;

            let response = request_sender
                .send_request(request)
                .await
                .context("Failed to send request")?;

            let body = response
                .into_body()
                .into_data_stream()
                .next()
                .await
                .context("Failed to read response body")??;

            let response: Response = serde_json::from_slice(&body)
                .context("Failed to parse response JSON")?;

            assert_eq!(response.message, "Hello, World!");
            anyhow::Ok(())
        })
        .await;

        server_handle.abort();
        let _ = server_handle.await;

        assert!(client_result.is_ok(), "Client test timed out or failed");
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(unix)]
    async fn test_serve_ipc_unix_with_client() -> anyhow::Result<()> {
        use hyper::client::conn;
        use hyperlocal::Uri;
        use tokio::{
            net::UnixStream,
            time::{Duration, timeout},
        };

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let socket_path = temp_dir.path().join("test_socket_unix_client");
        let router = test_router();

        let server_handle = tokio::spawn({
            let socket_path = socket_path.clone();
            async move {
                let _ = serve_ipc(router, socket_path.to_str().unwrap()).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_result = timeout(Duration::from_secs(5), async {
            use anyhow::Context as _;
            use bytes::Bytes;
            use futures::StreamExt;
            use http_body_util::{BodyExt, Empty};
            use hyper_util::rt::TokioIo;

            let stream = UnixStream::connect(&socket_path)
                .await
                .expect("Failed to connect to Unix socket");

            let io = TokioIo::new(stream);
            let (mut request_sender, connection) = conn::http1::handshake(io)
                .await
                .expect("Failed to handshake");

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Connection error: {}", e);
                }
            });

            let url = Uri::new(&socket_path, "/test");

            let request = hyper::Request::builder()
                .uri(url)
                .header("Host", "localhost")
                .body(Empty::<Bytes>::new())
                .context("Failed to build request")?;

            let response_body = request_sender
                .send_request(request)
                .await
                .context("Failed to send request")?
                .into_body()
                .into_data_stream()
                .next()
                .await
                .context("Failed to read response body")??;

            let response: Response = serde_json::from_slice(&response_body)
                .context("Failed to parse response JSON")?;

            assert_eq!(response.message, "Hello, World!");
            anyhow::Ok(())
        })
        .await;

        server_handle.abort();
        let _ = server_handle.await;

        assert!(client_result.is_ok(), "Client test timed out or failed");
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(unix)]
    async fn test_serve_ipc_unix_permission_denied() -> anyhow::Result<()> {
        use anyhow::Context;
        use std::{os::unix::fs::PermissionsExt, time::Duration};
        use tempfile::TempDir;
        use tokio::{fs, time::timeout};

        if uzers::get_current_uid() == 0 {
            return Ok(());
        }

        let router = test_router();
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test_socket");

        let mut perms = fs::metadata(temp_dir.path()).await.unwrap().permissions();
        perms.set_mode(0o444); // Read only
        fs::set_permissions(temp_dir.path(), perms).await.unwrap();

        let result = timeout(
            Duration::from_secs(5),
            serve_ipc(router, path.to_str().unwrap()),
        )
        .await;

        let mut perms = fs::metadata(temp_dir.path()).await.unwrap().permissions();
        perms.set_mode(0o755); // For cleaning
        fs::set_permissions(temp_dir.path(), perms).await.unwrap();

        let result = result.context("Test timed out")?;
        assert!(result.is_err());
        assert!(
            logs_contain("Cannot create IPC dir")
                || logs_contain("Cannot bind on IPC address")
        );
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(unix)]
    async fn test_serve_ipc_unix_multiple_clients() {
        use hyper::client::conn;
        use hyperlocal::Uri;
        use tokio::{
            net::UnixStream,
            time::{Duration, timeout},
        };

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let socket_path = temp_dir.path().join("test_socket_multi_clients");
        let router = test_router();

        let server_handle = tokio::spawn({
            let socket_path = socket_path.clone();
            async move {
                let _ = serve_ipc(router, socket_path.to_str().unwrap()).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut handles = vec![];
        for i in 0..3 {
            let socket_path = socket_path.clone();
            handles.push(tokio::spawn(async move {
                timeout(Duration::from_secs(5), async {
                    use anyhow::Context;
                    use bytes::Bytes;
                    use futures::StreamExt;
                    use http_body_util::{BodyExt, Empty};
                    use hyper_util::rt::TokioIo;

                    let stream = UnixStream::connect(&socket_path)
                        .await
                        .expect("Failed to connect to Unix socket");

                    let io = TokioIo::new(stream);
                    let (mut request_sender, connection) =
                        conn::http1::handshake(io)
                            .await
                            .expect("Failed to handshake");

                    tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            eprintln!("Connection error: {}", e);
                        }
                    });

                    let url = Uri::new(&socket_path, "/test");

                    let request = hyper::Request::builder()
                        .uri(url)
                        .header("Host", "localhost")
                        .body(Empty::<Bytes>::new())
                        .context("Failed to build request")?;

                    let response_body = request_sender
                        .send_request(request)
                        .await
                        .context("Failed to send request")?
                        .into_body()
                        .into_data_stream()
                        .next()
                        .await
                        .context("Failed to read response body")??;

                    let response: Response = serde_json::from_slice(&response_body)
                        .context("Failed to parse response JSON")?;

                    assert_eq!(response.message, "Hello, World!");
                    println!("Client {} received response: {}", i, response.message);
                    anyhow::Ok(())
                })
                .await
                .expect("Client test timed out")
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }

        server_handle.abort();
        let _ = server_handle.await;
    }
}
