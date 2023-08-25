use std::{net::SocketAddr, sync::Arc};

use axum::{routing::get, Router};

use tokio::sync::broadcast::Sender;
use tracing::info;

use crate::{config::internal::config::Controller, Runner};

use super::inbound::manager::ThreadSafeInboundManager;

mod handlers;
mod middlewares;

pub struct AppState {
    log_source_tx: Sender<String>,
}

pub fn get_api_runner(
    controller_cfg: Controller,
    log_source: Sender<String>,
    inbound_manager: ThreadSafeInboundManager,
) -> Option<Runner> {
    if let Some(bind_addr) = controller_cfg.external_controller {
        let app_state = Arc::new(AppState {
            log_source_tx: log_source,
        });
        let addr = bind_addr.parse().unwrap();

        let configs_router = handlers::config::routes(inbound_manager);

        let runner = async move {
            info!("Starting API server at {}", addr);
            let app = Router::new()
                .route("/", get(handlers::hello::handle))
                .route("/logs", get(handlers::log::handle))
                .route("/version", get(handlers::version::handle))
                .nest("/configs", configs_router)
                .layer(middlewares::auth::AuthMiddlewareLayer::new(
                    controller_cfg.secret.unwrap_or_default(),
                ))
                .with_state(app_state);
            axum::Server::bind(&addr)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .unwrap();
        };
        Some(Box::pin(runner))
    } else {
        None
    }
}
