use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Router};

use crate::app::{api::AppState, inbound::manager::ThreadSafeInboundManager};

#[derive(Clone)]
struct ConfigState {
    inbound_manager: ThreadSafeInboundManager,
}

pub fn routes(inbound_manager: ThreadSafeInboundManager) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/",
            get(get_configs).put(update_configs).patch(patch_configs),
        )
        .with_state(ConfigState { inbound_manager })
}

async fn get_configs(State(state): State<ConfigState>) -> impl IntoResponse {
    let ports = state.inbound_manager.lock().await.get_ports();
    axum::response::Json("get_configs")
}

async fn update_configs(State(state): State<ConfigState>) -> impl IntoResponse {
    axum::response::Json("update_configs")
}

async fn patch_configs(State(state): State<ConfigState>) -> impl IntoResponse {
    axum::response::Json("patch_configs")
}
