use std::{net::SocketAddr, sync::Arc};

use axum::{routing::get, Router};

use tokio::sync::broadcast::Sender;
use tracing::info;

use crate::{config::internal::config::Controller, Runner};

mod handlers;

pub struct AppState {
    log_source_tx: Sender<String>,
}

pub fn get_api_runner(controller_cfg: Controller, log_source: Sender<String>) -> Option<Runner> {
    if let Some(bind_addr) = controller_cfg.external_controller {
        let app_state = AppState {
            log_source_tx: log_source,
        };
        let addr = bind_addr.parse().unwrap();
        let runner = async move {
            info!("Starting API server at {}", addr);
            let app = Router::new()
                .route("/", get(handlers::hello::handle))
                .route("/logs", get(handlers::log::handle))
                .route("/version", get(handlers::version::handle))
                .with_state(Arc::new(app_state));
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
