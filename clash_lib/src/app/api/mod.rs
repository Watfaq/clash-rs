use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router as AxumRouter,
    response::Redirect,
    routing::{get, post},
};

use http::{Method, header};
use tokio::sync::{Mutex, broadcast::Sender};

use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{error, info};
use watfaq_error::{ErrContext, Result};
use watfaq_resolver::Resolver;

use crate::{GlobalState, Runner, config::internal::config::Controller};

use super::{
    dispatcher::{self, StatisticsManager},
    inbound::manager::InboundManager,
    logging::LogEvent,
    outbound::manager::ThreadSafeOutboundManager,
    profile::ThreadSafeCacheFile,
    router::{Router, ThreadSafeRouter},
};

mod handlers;
mod middlewares;

pub struct AppState {
    log_source_tx: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
}

#[allow(clippy::too_many_arguments)]
pub async fn controller_task(
    controller_cfg: Controller,
    log_source: Sender<LogEvent>,
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    resolver: Arc<Resolver>,
    outbound_manager: ThreadSafeOutboundManager,
    statistics_manager: Arc<StatisticsManager>,
    cache_store: ThreadSafeCacheFile,
    router: Arc<Router>,
    cwd: PathBuf,
) -> Result<()> {
    if let None = controller_cfg.external_controller {
        return Ok(());
    }
    let bind_addr = controller_cfg.external_controller.unwrap_or_default();
    let app_state = Arc::new(AppState {
        log_source_tx: log_source,
        statistics_manager: statistics_manager.clone(),
    });

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_origin(Any);

    let bind_addr = if bind_addr.starts_with(':') {
        info!("hostname not provided, listening on localhost");
        format!("localhost{}", bind_addr)
    } else {
        bind_addr
    };
    info!("Starting API server at {}", bind_addr);
    let mut app = AxumRouter::new()
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
                resolver.clone(),
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
        .nest("/dns", handlers::dns::routes(resolver))
        .route_layer(middlewares::auth::AuthMiddlewareLayer::new(
            controller_cfg.secret.unwrap_or_default(),
        ))
        .route_layer(cors)
        .with_state(app_state)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    if let Some(external_ui) = controller_cfg.external_ui {
        app = app
            .route("/ui", get(|| async { Redirect::to("/ui/") }))
            .nest_service("/ui/", ServeDir::new(cwd.join(external_ui)));
    }

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("API server error")
}
