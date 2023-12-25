use std::path::PathBuf;
use std::sync::Arc;

use axum::{response::Redirect, routing::get, Router};

use http::header;
use http::Method;
use tokio::sync::{broadcast::Sender, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::{error, info};

use crate::{config::internal::config::Controller, GlobalState, Runner};

use super::dispatcher::StatisticsManager;
use super::dns::ThreadSafeDNSResolver;
use super::logging::LogEvent;
use super::profile::ThreadSafeCacheFile;
use super::{
    dispatcher, inbound::manager::ThreadSafeInboundManager,
    outbound::manager::ThreadSafeOutboundManager, router::ThreadSafeRouter,
};

mod handlers;
mod middlewares;

pub struct AppState {
    log_source_tx: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
}

pub fn get_api_runner(
    controller_cfg: Controller,
    log_source: Sender<LogEvent>,
    inbound_manager: ThreadSafeInboundManager,
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

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
            .allow_origin(Any);

        let runner = async move {
            info!("Starting API server at {}", bind_addr);
            let mut app = Router::new()
                .route("/", get(handlers::hello::handle))
                .route("/logs", get(handlers::log::handle))
                .route("/traffic", get(handlers::traffic::handle))
                .route("/version", get(handlers::version::handle))
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
                .route_layer(middlewares::auth::AuthMiddlewareLayer::new(
                    controller_cfg.secret.unwrap_or_default(),
                ))
                .route_layer(cors)
                .with_state(app_state);

            if let Some(external_ui) = controller_cfg.external_ui {
                app = app
                    .route("/ui", get(|| async { Redirect::to("/ui/") }))
                    .nest_service("/ui/", ServeDir::new(PathBuf::from(cwd).join(external_ui)));
            }

            let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();

            axum::serve(listener, app).await.map_err(|x| {
                error!("API server error: {}", x);
                crate::Error::Operation(format!("API server error: {}", x))
            })
        };
        Some(Box::pin(runner))
    } else {
        None
    }
}
