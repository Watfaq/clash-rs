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
