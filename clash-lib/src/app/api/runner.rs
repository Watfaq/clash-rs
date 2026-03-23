use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router, ServiceExt, middleware,
    response::Redirect,
    routing::{get, post},
};
use tower::{Layer, util::MapRequestLayer};

use http::{Method, header};
use tokio::sync::{Mutex, broadcast::Sender};
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{debug, error, info, warn};

use crate::{
    GlobalState,
    app::{
        api::{
            AppState, handlers, ipc, middlewares,
            middlewares::websocket_uri_rewrite::rewrite_websocket_uri,
        },
        dispatcher::{self, StatisticsManager},
        dns::{ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::InboundManager,
        logging::LogEvent,
        outbound::manager::ThreadSafeOutboundManager,
        profile::ThreadSafeCacheFile,
        router::ThreadSafeRouter,
    },
    config::config::Controller,
    runner::Runner,
};

pub struct ApiRunner {
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

    cancellation_token: tokio_util::sync::CancellationToken,
    dns_listen_addr: DNSListenAddr,
    dns_enabled: bool,
}

impl ApiRunner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
        dns_listen_addr: DNSListenAddr,
        dns_enabled: bool,
    ) -> Self {
        Self {
            controller_cfg,
            log_source,
            inbound_manager,
            dispatcher,
            global_state,
            dns_resolver,
            outbound_manager,
            statistics_manager,
            cache_store,
            router,
            cwd,
            cancellation_token: cancellation_token.unwrap_or_default(),
            dns_listen_addr,
            dns_enabled,
        }
    }
}

impl Runner for ApiRunner {
    fn run_async(&self) {
        let inbound_manager = self.inbound_manager.clone();
        let dispatcher = self.dispatcher.clone();
        let global_state = self.global_state.clone();
        let dns_resolver = self.dns_resolver.clone();
        let outbound_manager = self.outbound_manager.clone();
        let statistics_manager = self.statistics_manager.clone();
        let cache_store = self.cache_store.clone();
        let controller_cfg = self.controller_cfg.clone();
        let router = self.router.clone();
        let cwd = self.cwd.clone();
        let dns_listen_addr = self.dns_listen_addr.clone();
        let dns_enabled = self.dns_enabled;

        let ipc_addr = controller_cfg.external_controller_ipc;
        let tcp_addr = controller_cfg.external_controller;

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

        let app_state = Arc::new(AppState {
            log_source_tx: self.log_source.clone(),
            statistics_manager: statistics_manager.clone(),
        });
        let cancellation_token = self.cancellation_token.clone();
        tokio::spawn(async move {
            let mut router = Router::new()
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
                        dns_listen_addr,
                        dns_enabled,
                    ),
                )
                .nest("/rules", handlers::rule::routes(router))
                .nest("/group", handlers::group::routes(outbound_manager.clone()))
                .nest(
                    "/proxies",
                    handlers::proxy::routes(outbound_manager.clone(), cache_store),
                )
                .nest(
                    "/providers/proxies",
                    handlers::provider::routes(outbound_manager),
                )
                .nest(
                    "/connections",
                    handlers::connection::routes(statistics_manager),
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

            if let Some(external_ui) = controller_cfg.external_ui {
                router = router
                    .route("/ui", get(|| async { Redirect::to("/ui/") }))
                    .nest_service(
                        "/ui/",
                        ServeDir::new(PathBuf::from(cwd).join(external_ui)),
                    );
            }

            // Create display strings before moving values
            let tcp_addr_display = tcp_addr.as_ref().map(|addr| addr.to_string());
            let ipc_addr_display = ipc_addr.clone();

            // Handle TCP listening
            let tcp_fut = if let Some(bind_addr) = tcp_addr {
                let bind_addr = if bind_addr.starts_with(':') {
                    info!(
                        "TCP API Server address not supplied, listening on \
                         `127.0.0.1`"
                    );
                    format!("127.0.0.1{bind_addr}")
                } else {
                    bind_addr
                };
                let router_clone = router.clone();
                Some(async move {
                    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
                    info!(
                        "API server is listening on TCP address {}",
                        listener.local_addr()?
                    );
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
                                "Please set a secret in the configuration to \
                                 secure the API server."
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
                    let app = MapRequestLayer::new(rewrite_websocket_uri)
                        .layer(router_clone);
                    axum::serve(
                        listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
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
            let ipc_fut = ipc_addr.as_ref().map(|ipc_path| {
                let ipc_path = ipc_path.clone();
                async move { ipc::serve_ipc(router, &ipc_path).await }
            });

            let result = match (tcp_fut, ipc_fut) {
                (Some(tcp), Some(ipc)) => {
                    debug!(
                        "API server is running on both TCP {} and IPC {}",
                        tcp_addr_display.unwrap_or_default(),
                        ipc_addr_display.unwrap_or_default()
                    );
                    tokio::select! {
                        result = tcp => result,
                        result = ipc => result,
                        _ = cancellation_token.cancelled() => {
                            info!("All API server closed");
                            Ok(())
                        }
                    }
                }
                (Some(tcp), None) => {
                    debug!(
                        "API server is running on TCP {}",
                        tcp_addr_display.clone().unwrap_or_default()
                    );
                    tokio::select! {
                        result = tcp => result,
                        _ = cancellation_token.cancelled() => {
                            info!("TCP API server is closed");
                            Ok(())
                        }
                    }
                }
                (None, Some(ipc)) => {
                    debug!(
                        "API server is running on IPC {}",
                        ipc_addr_display.unwrap_or_default()
                    );
                    tokio::select! {
                        result = ipc => result,
                        _ = cancellation_token.cancelled() => {
                            info!("IPC API server is closed");
                            Ok(())
                        }
                    }
                }
                (None, None) => {
                    info!("API server: no listener configured, skipping");
                    Ok(())
                }
            };
            if let Err(e) = result {
                error!("API server failed to start, error: {}", e);
            }
        });
    }

    fn shutdown(&self) {
        info!("Shutting down API server");
        self.cancellation_token.cancel();
    }

    fn join(&self) -> futures::future::BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move { Ok(()) })
    }
}
