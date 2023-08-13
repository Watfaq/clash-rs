use axum::{routing::get, Router};
use tracing::info;

use crate::{config::internal::config::Controller, Runner};

async fn root() -> &'static str {
    "Hello, World!"
}

pub fn get_api_runner(controller_cfg: Controller) -> Option<Runner> {
    if let Some(bind_addr) = controller_cfg.external_controller {
        let addr = bind_addr.parse().unwrap();
        let runner = async move {
            info!("Starting API server at {}", addr);
            let app = Router::new().route("/", get(root));
            axum::Server::bind(&addr)
                .serve(app.into_make_service())
                .await
                .unwrap();
        };
        Some(Box::pin(runner))
    } else {
        None
    }
}
