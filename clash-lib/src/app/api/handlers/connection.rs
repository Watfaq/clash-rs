use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{
        Path, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
    routing::{delete, get},
};

use serde::Deserialize;
use tracing::{debug, warn};

use crate::app::{
    api::{CtrlResult, CtrlState},
    dispatcher::StatisticsManager,
};

pub fn routes(ctrl_state: Arc<CtrlState>) -> Router<Arc<CtrlState>> {
    Router::new()
        .route("/", get(get_connections).delete(close_all_connection))
        .route("/{id}", delete(close_connection))
        .with_state(ctrl_state)
}

#[derive(Deserialize)]
pub struct GetConnectionsQuery {
    pub interval: Option<u64>,
}

pub async fn get_connections(
    State(state): State<Arc<CtrlState>>,
) -> CtrlResult<impl IntoResponse> {
    let snapshot = state.statistics_manager.snapshot().await;

    Ok(serde_json::to_string(&snapshot)?)
}

pub async fn close_connection(
    State(state): State<Arc<CtrlState>>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    state.statistics_manager.close(id).await;
    format!("connection {id} closed").into_response()
}

pub async fn close_all_connection(
    State(state): State<Arc<CtrlState>>,
) -> impl IntoResponse {
    state.statistics_manager.close_all().await;
    "all connections closed".into_response()
}
