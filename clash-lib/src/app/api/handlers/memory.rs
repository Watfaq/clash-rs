use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{ConnectInfo, Query, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
};
use http::HeaderMap;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::app::api::{AppState, handlers::utils::is_request_websocket};

#[derive(Deserialize)]
pub struct GetMemoryQuery {
    pub interval: Option<u64>,
}

#[derive(serde::Serialize)]
pub struct GetMemoryResponse {
    pub inuse: usize,
    pub oslimit: usize,
}

pub async fn handle(
    headers: HeaderMap,
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<GetMemoryQuery>,
) -> impl IntoResponse {
    if !is_request_websocket(headers) {
        // REST request - return single response
        let mgr = state.statistics_manager.clone();
        let snapshot = GetMemoryResponse {
            inuse: mgr.memory_usage(),
            oslimit: 0,
        };
        return Json(snapshot).into_response();
    }

    // WebSocket request - stream memory usage
    let interval_secs = q.interval.unwrap_or(1);
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {} with {}", e, addr);
    })
    .on_upgrade(move |mut socket| async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;
            let mgr = state.statistics_manager.clone();
            let snapshot = GetMemoryResponse {
                inuse: mgr.memory_usage(),
                oslimit: 0,
            };

            let body = match serde_json::to_string(&snapshot) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to serialize memory stats: {}", e);
                    continue;
                }
            };

            if let Err(e) = socket.send(Message::Text(body.into())).await {
                debug!("ws connection closed: {}", e);
                break;
            }
        }
    })
}
