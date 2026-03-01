use std::{path::PathBuf, sync::Arc};

use axum::{
    Router, ServiceExt, middleware,
    response::{IntoResponse, Redirect, Response},
    routing::{any, get, post},
};
use http::{Method, StatusCode, header};
use tokio::sync::{Mutex, broadcast::Sender};
use tower::{Layer, util::MapRequestLayer};
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::ServeDir,
};
use tracing::{error, info, warn};

use crate::{
    GlobalState, Runner,
    app::api::handlers::connection::{self},
    config::internal::config::Controller,
};

use super::{
    dispatcher::{self, StatisticsManager},
    dns::ThreadSafeDNSResolver,
    inbound::manager::InboundManager,
    logging::LogEvent,
    outbound::manager::ThreadSafeOutboundManager,
    profile::ThreadSafeCacheFile,
    router::ArcRouter,
};

mod handlers;
mod ipc;
mod middlewares;
mod websocket;

pub struct CtrlState {
    log_source_tx: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
}

struct CtrlError(anyhow::Error);
type CtrlResult<T> = std::result::Result<T, CtrlError>;

impl<E> From<E> for CtrlError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl IntoResponse for CtrlError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Controller Internal Error: {}", self.0),
        )
            .into_response()
    }
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
    router: ArcRouter,
    cwd: String,
) -> Option<Runner> {
    let ipc_addr = controller_cfg.external_controller_ipc;
    let tcp_addr = controller_cfg.external_controller.filter(|v| !v.is_empty());

    let ctrl_state = Arc::new(CtrlState {
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
        let mut router = Router::new()
            .route("/", get(handlers::hello::handle))
            .route("/version", get(handlers::version::handle))
            .route("/memory", any(handlers::memory::handle))
            .route("/restart", post(handlers::restart::handle))
            .nest("/ws", websocket::routes(ctrl_state.clone()))
            .nest(
                "/configs",
                handlers::config::routes(
                    inbound_manager,
                    dispatcher,
                    global_state,
                    dns_resolver.clone(),
                ),
            )
            .nest("/rules", handlers::rule::routes(router.clone()))
            .nest("/group", handlers::group::routes(outbound_manager.clone()))
            .nest(
                "/proxies",
                handlers::proxy::routes(outbound_manager.clone(), cache_store),
            )
            .nest(
                "/providers/proxies",
                handlers::provider::routes(outbound_manager),
            )
            .nest("/connections", connection::routes(ctrl_state.clone()))
            .nest("/dns", handlers::dns::routes(dns_resolver))
            .with_state(ctrl_state)
            .layer(middleware::from_fn(
                middlewares::fix_json_content_type::fix_content_type,
            ));

        if let Some(external_ui) = controller_cfg.external_ui {
            router = router
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
            let router_clone = router
                .clone()
                .route_layer(middlewares::auth::AuthMiddlewareLayer::new(
                    controller_cfg.secret.clone().unwrap_or_default(),
                ))
                .route_layer(cors);
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
                let service = MapRequestLayer::new(
                    middlewares::websocket_uri_rewrite::rewrite_websocket_uri,
                )
                .layer(router_clone)
                .into_make_service();

                axum::serve(listener, service).await.map_err(|x| {
                    error!("TCP API server error: {}", x);
                    crate::Error::Operation(format!("API server error: {x}"))
                })
            })
        } else {
            None
        };
        // Handle IPC listening
        let ipc_fut = ipc_addr
            .map(|ipc_path| async move { ipc::serve_ipc(router, &ipc_path).await });
        match (tcp_fut, ipc_fut) {
            (Some(tcp), Some(ipc)) => {
                tokio::select! {
                    result = tcp => result,
                    result = ipc => result,
                }
            }
            (Some(tcp), None) => tcp.await,
            (None, Some(ipc)) => ipc.await,
            (None, None) => Ok(()),
        }
    };
    Some(Box::pin(runner))
}
