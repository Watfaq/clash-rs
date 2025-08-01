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
    if let Some(bind_addr) = controller_cfg.external_controller {
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

        let bind_addr = if bind_addr.starts_with(':') {
            info!("hostname not provided, listening on localhost");
            format!("127.0.0.1{bind_addr}")
        } else {
            bind_addr
        };

        let runner = async move {
            info!("Starting API server at {}", bind_addr);
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

            if let Some(external_ui) = controller_cfg.external_ui {
                app = app
                    .route("/ui", get(|| async { Redirect::to("/ui/") }))
                    .nest_service(
                        "/ui/",
                        ServeDir::new(PathBuf::from(cwd).join(external_ui)),
                    );
            }

            let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
            if let Ok(addr) = listener.local_addr() {
                if !addr.ip().is_loopback()
                    && controller_cfg.secret.unwrap_or_default().is_empty()
                {
                    error!(
                        "API server is listening on a non-loopback address without \
                         a secret. This is insecure!"
                    );
                    error!(
                        "Please set a secret in the configuration to secure the \
                         API server."
                    );
                    return Err(crate::Error::Operation(
                        "API server is listening on a non-loopback address without \
                         a secret. This is insecure!"
                            .to_string(),
                    ));
                }
                if !addr.ip().is_loopback()
                    && controller_cfg.cors_allow_origins.is_none()
                {
                    error!(
                        "API server is listening on a non-loopback address without \
                         CORS origins configured. This is insecure!"
                    );
                    error!(
                        "Please set CORS origins in the configuration to secure \
                         the API server."
                    );
                    return Err(crate::Error::Operation(
                        "API server is listening on a non-loopback address without \
                         CORS origins configured. This is insecure!"
                            .to_string(),
                    ));
                }
            }

            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(|x| {
                error!("API server error: {}", x);
                crate::Error::Operation(format!("API server error: {x}"))
            })
        };
        Some(Box::pin(runner))
    } else {
        None
    }
}
