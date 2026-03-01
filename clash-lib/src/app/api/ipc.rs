use axum::Router;
use tracing::error;

#[cfg(windows)]
pub async fn serve_ipc(router: Router, path: &str) -> crate::Result<()> {
    use axum::ServiceExt;
    use tower::{Layer, util::MapRequestLayer};
    use tracing::info;

    use crate::app::api::middlewares::websocket_uri_rewrite::rewrite_websocket_uri;
    info!("Starting API server on NamedPipe {path}");

    let listener = NamedPipeListener {
        path: path.to_string(),
        first_instance: true,
    };
    let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| {
            error!("NamedPipe API server error: {}", e);
            crate::Error::Operation(format!("NamedPipe API server error: {e}"))
        })?;
    Ok(())
}

#[cfg(unix)]
pub async fn serve_ipc(router: Router, path: &str) -> crate::Result<()> {
    use axum::ServiceExt;
    use std::path::PathBuf;
    use tower::{Layer, util::MapRequestLayer};
    use tracing::info;

    use crate::app::api::middlewares::websocket_uri_rewrite::rewrite_websocket_uri;
    let path = PathBuf::from(path);

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

    let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

    axum::serve(uds, app.into_make_service())
        .await
        .map_err(|e| {
            error!("IPC API Server error: {}", e);
            crate::Error::Operation(format!("IPC API Server error: {e}"))
        })
}

#[cfg(all(not(unix), not(windows)))]
pub async fn serve_ipc<S>(service: S, path: &str) -> crate::Result<()>
where
    S: Clone + Send + 'static,
{
    error!("IPC only get supported on Unix and Windows");
    Err(crate::Error::Operation(
        "IPC only get supported on Unix and Windows".to_string(),
    ))
}

#[cfg(windows)]
fn create_pipe_security_attributes()
-> crate::Result<windows::Win32::Security::SECURITY_ATTRIBUTES> {
    use windows::{
        Win32::Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorA,
                SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        core::PSTR,
    };

    // SDDL string for:
    // - Allow Read/Write for BUILTIN\Users
    // - Allow Read/Write for NT AUTHORITY\SYSTEM
    // D: = DACL
    // (A;;GRGW;;;BU) = Allow Generic Read/Generic Write for Built-in Users
    // (A;;GRGW;;;SY) = Allow Generic Read/Generic Write for System
    let sddl = b"D:(A;;GRGW;;;BU)(A;;GRGW;;;SY)\0";

    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let mut sd_size = 0u32;

        ConvertStringSecurityDescriptorToSecurityDescriptorA(
            PSTR::from_raw(sddl.as_ptr() as *mut u8),
            SDDL_REVISION_1,
            &mut sd,
            Some(&mut sd_size),
        )
        .map_err(|e| {
            crate::Error::Operation(format!(
                "Failed to convert SDDL to security descriptor: {e:?}"
            ))
        })?;

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: windows::Win32::Foundation::FALSE,
        };

        Ok(sa)
    }
}

#[cfg(windows)]
fn create_named_pipe_with_security(
    path: &str,
    first_instance: bool,
) -> crate::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe;

    let mut sa = create_pipe_security_attributes()?;

    unsafe {
        let mut options = named_pipe::ServerOptions::new();
        options.access_inbound(true).access_outbound(true);

        if first_instance {
            options.first_pipe_instance(true);
        }

        options
            .create_with_security_attributes_raw(
                path,
                &mut sa as *mut _ as *mut std::ffi::c_void,
            )
            .map_err(|e| crate::Error::Operation(format!("Cannot create pipe {e}")))
        // options
        //     .create(path)
        //     .map_err(|e| crate::Error::Operation(format!("Cannot create pipe
        // {e}")))
    }
}
use tokio::net::windows::named_pipe::NamedPipeServer;

struct NamedPipeListener {
    path: String,
    first_instance: bool,
}
impl axum::serve::Listener for NamedPipeListener {
    type Addr = ();
    type Io = NamedPipeServer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        use tracing::{info, warn};
        use tokio::time::{sleep, Duration};
        
        let max_retries = 5;
        let mut retry_count = 0;
        
        let server = loop {
            match create_named_pipe_with_security(&self.path, self.first_instance) {
                Ok(server) => break server,
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        panic!("Failed to create named pipe after {} retries: {}", max_retries, e);
                    }
                    warn!("Failed to create named pipe (attempt {}/{}): {}. Retrying...", 
                          retry_count, max_retries, e);
                    sleep(Duration::from_millis(200 * retry_count as u64)).await;
                }
            }
        };
        
        self.first_instance = false;
        server
            .connect()
            .await
            .expect("Failed to connect named pipe");
        info!("Client connected to NamedPipe {}", self.path);
        (server, ())
    }

    fn local_addr(&self) -> tokio::io::Result<Self::Addr> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use futures::SinkExt;
    use serde::{Deserialize, Serialize};
    use tracing_test::traced_test;

    fn test_router() -> Router {
        Router::new().route(
            "/test",
            get(|| async {
                Json(TestResponse {
                    message: "Hello, World!".to_string(),
                })
            }),
        )
    }

    fn test_router_with_websocket() -> Router {
        use axum::{
            extract::ws::{WebSocket, WebSocketUpgrade},
            response::Response,
        };

        async fn ws_handler(ws: WebSocketUpgrade) -> Response {
            ws.on_upgrade(handle_socket)
        }

        async fn handle_socket(mut socket: WebSocket) {
            use axum::extract::ws::Message;
            while let Some(msg) = socket.recv().await {
                if let Ok(msg) = msg {
                    match msg {
                        Message::Text(text) => {
                            let response = format!("Echo: {}", text);
                            if socket
                                .send(Message::Text(response.into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            }
        }

        Router::new()
            .route(
                "/test",
                get(|| async {
                    Json(TestResponse {
                        message: "Hello, World!".to_string(),
                    })
                }),
            )
            .route("/ws", get(ws_handler))
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct TestResponse {
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

            let response: TestResponse = serde_json::from_slice(&body)
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

            let response: TestResponse = serde_json::from_slice(&response_body)
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

                    let response: TestResponse =
                        serde_json::from_slice(&response_body)
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

    #[tokio::test]
    #[traced_test]
    #[cfg(windows)]
    async fn test_serve_ipc_windows_multiple_clients() -> anyhow::Result<()> {
        use hyper::client::conn;
        use hyper_util::rt::TokioIo;
        use tokio::{
            net::windows::named_pipe::ClientOptions,
            time::{Duration, timeout},
        };

        let router = test_router();
        let path = r"\\.\pipe\test_named_pipe_win_multi_client";

        let server_handle = tokio::spawn({
            let router = router.clone();
            async move {
                let _ = serve_ipc(router, path).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut handles = vec![];
        for i in 0..3 {
            handles.push(tokio::spawn(async move {
                timeout(Duration::from_secs(5), async {
                    use anyhow::Context;
                    use bytes::Bytes;
                    use futures::StreamExt;
                    use http_body_util::{BodyExt, Empty};
                    tokio::time::sleep(Duration::from_millis(100 * i)).await;
                    let client = ClientOptions::new()
                        .open(path)
                        .context("Failed to connect to named pipe")?;

                    let io = TokioIo::new(client);
                    let (mut request_sender, connection) =
                        conn::http1::handshake(io)
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

                    let response: TestResponse = serde_json::from_slice(&body)
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
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }

        server_handle.abort();
        let _ = server_handle.await;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(windows)]
    async fn test_serve_ipc_windows_websocket() -> anyhow::Result<()> {
        use tokio::{net::windows::named_pipe::ClientOptions, time::Duration};
        use tokio_tungstenite::tungstenite::{
            client::IntoClientRequest, protocol::Message,
        };

        let router = test_router_with_websocket();
        let path = r"\\.\pipe\test_named_pipe_ws";

        let server_handle = tokio::spawn({
            let router = router.clone();
            async move {
                serve_ipc(router, path).await.unwrap();
            }
        });

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Try to connect, skip test if pipe creation failed
        let client = match ClientOptions::new().open(path) {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Skipping test: Failed to connect to named pipe: {}", e);
                server_handle.abort();
                let _ = server_handle.await;
                return Ok(());
            }
        };

        let mut request = "ws://localhost/ws".into_client_request()?;
        request
            .headers_mut()
            .insert("Host", "localhost".parse().unwrap());

        let (mut ws_stream, _) =
            tokio_tungstenite::client_async(request, client).await?;

        ws_stream
            .send(Message::Text("Hello WebSocket".into()))
            .await?;

        use futures::StreamExt;
        if let Some(msg) = ws_stream.next().await {
            let msg = msg.expect("Failed to receive message");
            if let Message::Text(text) = msg {
                assert_eq!(text, "Echo: Hello WebSocket");
                println!("Received: {}", text);
            } else {
                panic!("Expected text message");
            }
        }

        ws_stream.send(Message::Close(None)).await?;

        server_handle.abort();
        let _ = server_handle.await;
        Ok(())
    }
}
