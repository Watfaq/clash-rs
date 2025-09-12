use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router, middleware,
    response::Redirect,
    routing::{get, post},
};
use http::{Method, header};
use tokio::sync::{Mutex, broadcast::Sender};
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{error, info, warn};

use crate::{GlobalState, Runner, config::internal::config::Controller};

use super::{
    dispatcher::{self, StatisticsManager},
    dns::ThreadSafeDNSResolver,
    inbound::manager::InboundManager,
    logging::LogEvent,
    outbound::manager::ThreadSafeOutboundManager,
    profile::ThreadSafeCacheFile,
    router::ThreadSafeRouter,
};

mod handlers;
mod middlewares;

pub struct AppState {
    log_source_tx: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
}

#[allow(clippy::too_many_arguments)]
pub fn get_api_runner(
    controller_cfg: Controller,
    log_source: Sender<LogEvent>,
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: ThreadSafeOutboundManager,
    statistics_manager: Arc<StatisticsManager>,
    cache_store: ThreadSafeCacheFile,
    router: ThreadSafeRouter,
    cwd: String,
) -> Option<Runner> {
    let ipc_addr = controller_cfg.external_controller_ipc;
    let tcp_addr = controller_cfg.external_controller;

    if tcp_addr.is_none() && ipc_addr.is_none() {
        return None;
    }

    let app_state = Arc::new(AppState {
        log_source_tx: log_source,
        statistics_manager: statistics_manager.clone(),
    });

    let origins: AllowOrigin =
        if let Some(origins) = &controller_cfg.cors_allow_origins {
            origins
                .iter()
                .filter_map(|v| match v.parse() {
                    Ok(origin) => Some(origin),
                    Err(e) => {
                        warn!("ignored invalid CORS origin '{}': {}", v, e);
                        None
                    }
                })
                .collect::<Vec<_>>()
                .into()
        } else {
            Any.into()
        };

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_private_network(true)
        .allow_origin(origins);

    let runner = async move {
        info!("Starting API server");
        let mut app = Router::new()
            .route("/", get(handlers::hello::handle))
            .route("/logs", get(handlers::log::handle))
            .route("/traffic", get(handlers::traffic::handle))
            .route("/version", get(handlers::version::handle))
            .route("/memory", get(handlers::memory::handle))
            .route("/restart", post(handlers::restart::handle))
            .nest(
                "/configs",
                handlers::config::routes(
                    inbound_manager,
                    dispatcher,
                    global_state,
                    dns_resolver.clone(),
                ),
            )
            .nest("/rules", handlers::rule::routes(router))
            .nest(
                "/proxies",
                handlers::proxy::routes(outbound_manager.clone(), cache_store),
            )
            .nest(
                "/connections",
                handlers::connection::routes(statistics_manager),
            )
            .nest(
                "/providers/proxies",
                handlers::provider::routes(outbound_manager),
            )
            .nest("/dns", handlers::dns::routes(dns_resolver))
            .route_layer(cors)
            .with_state(app_state)
            .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

        if let Some(external_ui) = controller_cfg.external_ui {
            app = app
                .route("/ui", get(|| async { Redirect::to("/ui/") }))
                .nest_service(
                    "/ui/",
                    ServeDir::new(PathBuf::from(cwd).join(external_ui)),
                );
        }
        // Handle TCP listening
        let tcp_fut = if let Some(bind_addr) = tcp_addr {
            let bind_addr = if bind_addr.starts_with(':') {
                info!(
                    "TCP API Server address not supplied, listening on `localhost`"
                );
                format!("127.0.0.1{bind_addr}")
            } else {
                bind_addr
            };
            let app_clone = app.clone().route_layer(
                middlewares::auth::AuthMiddlewareLayer::new(
                    controller_cfg.secret.clone().unwrap_or_default(),
                ),
            );
            Some(async move {
                info!("Starting API server on TCP address {bind_addr}");
                let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
                // TCP related security checks
                if let Ok(addr) = listener.local_addr() {
                    if !addr.ip().is_loopback()
                        && controller_cfg.secret.unwrap_or_default().is_empty()
                    {
                        error!(
                            "API server is listening on a non-loopback address \
                             without a secret. This is insecure!"
                        );
                        error!(
                            "Please set a secret in the configuration to secure \
                             the API server."
                        );
                        return Err(crate::Error::Operation(
                            "API server is listening on a non-loopback address \
                             without a secret. This is insecure!"
                                .to_string(),
                        ));
                    }
                    if !addr.ip().is_loopback()
                        && controller_cfg.cors_allow_origins.is_none()
                    {
                        error!(
                            "API server is listening on a non-loopback address \
                             without CORS origins configured. This is insecure!"
                        );
                        error!(
                            "Please set CORS origins in the configuration to \
                             secure the API server."
                        );
                        return Err(crate::Error::Operation(
                            "API server is listening on a non-loopback address \
                             without CORS origins configured. This is insecure!"
                                .to_string(),
                        ));
                    }
                }
                axum::serve(
                    listener,
                    app_clone.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .nest("/rules", handlers::rule::routes(router))
                .nest(
                    "/proxies",
                    handlers::proxy::routes(outbound_manager.clone(), cache_store),
                )
                .nest("/group", handlers::group::routes(outbound_manager.clone()))
                .nest(
                    "/connections",
                    handlers::connection::routes(statistics_manager),
                )
                .nest(
                    "/providers/proxies",
                    handlers::provider::routes(outbound_manager),
                )
                .nest("/dns", handlers::dns::routes(dns_resolver))
                .route_layer(middlewares::auth::AuthMiddlewareLayer::new(
                    controller_cfg.secret.clone().unwrap_or_default(),
                ))
                .layer(middleware::from_fn(
                    middlewares::fix_json_content_type::fix_content_type,
                ))
                .route_layer(cors)
                .with_state(app_state)
                .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));
                .await
                .map_err(|x| {
                    error!("TCP API server error: {}", x);
                    crate::Error::Operation(format!("API server error: {x}"))
                })
            })
        } else {
            None
        };
        // Handle IPC listening
        let ipc_fut = if let Some(ipc_path) = ipc_addr {
            #[cfg(unix)]
            {
                use axum::{
                    extract::connect_info::Connected, serve::IncomingStream,
                };
                use tokio::net::UnixListener;
                let path = PathBuf::from(ipc_path);
                let app_clone = app.clone();
                Some(async move {
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
                            crate::Error::Operation(format!(
                                "Cannot create IPC dir: {e}"
                            ))
                        })?;
                    }

                    let uds =
                        tokio::net::UnixListener::bind(&path).map_err(|e| {
                            crate::Error::Operation(format!(
                                "Cannot bind on IPC address: {e}"
                            ))
                        })?;

                    #[derive(Clone, Debug)]
                    #[allow(dead_code)]
                    struct UdsConnectInfo {
                        peer_addr: Arc<tokio::net::unix::SocketAddr>,
                        peer_cred: tokio::net::unix::UCred,
                    }

                    impl Connected<IncomingStream<'_, UnixListener>> for UdsConnectInfo {
                        fn connect_info(
                            stream: IncomingStream<'_, UnixListener>,
                        ) -> Self {
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
                        app_clone
                            .into_make_service_with_connect_info::<UdsConnectInfo>(),
                    )
                    .await
                    .map_err(|e| {
                        error!("IPC API Server error: {}", e);
                        crate::Error::Operation(format!("IPC API Server error: {e}"))
                    })
                })
            }
            #[cfg(windows)]
            {
                use tokio::net::windows::named_pipe::ServerOptions;

                info!("Starting API server on NamedPipe {ipc_path}");
                let pipe_name = ipc_path;
                let app_clone = app.clone();
                let server = ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(&pipe_name)
                    .map_err(|e| {
                        crate::Error::Operation(format!("Cannot create pipe {e}"))
                    })?;
                Some(async move {
                    let mut server = server;
                    loop {
                        server.connect().await.map_err(|e| {
                            crate::Error::Operation(format!("NamedPipe error: {e}"))
                        })?;
                        let connected_client = server;
                        server = ServerOptions::new()
                            .first_pipe_instance(true)
                            .create(&pipe_name)
                            .map_err(|e| {
                                crate::Error::Operation(format!(
                                    "Cannot create pipe: {e}"
                                ))
                            })?;
                        let app_clone = app_clone.clone();
                        tokio::spawn(async move {
                            use hyper_util::rt::TokioIo;

                            let io = TokioIo::new(connected_client);
                            let hyper_service = hyper::service::service_fn(
                                move |request: hyper::Request<
                                    hyper::body::Incoming,
                                >| {
                                    use tower::Service as _;

                                    app_clone.clone().call(request)
                                },
                            );

                            if let Err(e) =
                                hyper::server::conn::http1::Builder::new()
                                    .serve_connection(io, hyper_service)
                                    .await
                            {
                                error!("NamedPipe error: {}", e);
                            }
                        });
                    }
                })
            }
            #[cfg(all(not(unix), not(windows)))]
            {
                error!("IPC only get supported on Unix and Windows");
                Some(async move {
                    Err(crate::Error::Operation(
                        "IPC only get supported on Unix and Windows".to_string(),
                    ))
                })
            }
        } else {
            None
        };
        match (tcp_fut, ipc_fut) {
            (Some(tcp), Some(ipc)) => {
                tokio::select! {
                    result = tcp => result,
                    result = ipc => result,
                }
            }
            (Some(tcp), None) => tcp.await,
            (None, Some(ipc)) => ipc.await,
            (None, None) => unreachable!(),
        }
    };
    Some(Box::pin(runner))
}
