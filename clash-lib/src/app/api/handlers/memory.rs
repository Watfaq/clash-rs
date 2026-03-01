use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::app::api::CtrlState;

#[derive(Deserialize)]
pub struct GetMemoryQuery {
    interval: Option<u64>,
}

#[derive(Serialize)]
struct GetMemoryResponse {
    inuse: usize,
    oslimit: usize,
}

pub async fn handle(State(state): State<Arc<CtrlState>>) -> impl IntoResponse {
    let mgr = state.statistics_manager.clone();
    let snapshot = GetMemoryResponse {
        inuse: mgr.memory_usage(),
        oslimit: 0,
    };
    return Json(snapshot).into_response();
}

