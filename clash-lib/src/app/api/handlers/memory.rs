use std::sync::Arc;

use axum::{Json, extract::State, response::IntoResponse};

use serde::Serialize;

use crate::app::api::AppState;

#[derive(Serialize)]
pub struct GetMemoryResponse {
    pub inuse: usize,
    pub oslimit: usize,
}

pub async fn handle(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mgr = state.statistics_manager.clone();
    let snapshot = GetMemoryResponse {
        inuse: mgr.memory_usage(),
        oslimit: 0,
    };
    Json(snapshot).into_response()
}
