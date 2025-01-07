use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ws::Message, FromRequest, Query, Request, State, WebSocketUpgrade},
    response::IntoResponse,
    Json,
};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::app::api::AppState;

use super::utils::is_request_websocket;

#[derive(Deserialize)]
pub struct GetMemoryQuery {
    interval: Option<u64>,
}

#[derive(Serialize)]
struct GetMemoryResponse {
    inuse: usize,
    oslimit: usize,
}
pub async fn handle(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    q: Query<GetMemoryQuery>,
    req: Request<Body>,
) -> impl IntoResponse {
    if !is_request_websocket(headers) {
        let mgr = state.statistics_manager.clone();
        let snapshot = GetMemoryResponse {
            inuse: mgr.memory_usage(),
            oslimit: 0,
        };
        return Json(snapshot).into_response();
    }

    let ws = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!("ws upgrade error: {}", e);
            return e.into_response();
        }
    };

    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        let interval = q.interval;

        let mgr = state.statistics_manager.clone();

        loop {
            let snapshot = GetMemoryResponse {
                inuse: mgr.memory_usage(),
                oslimit: 0,
            };
            let j = serde_json::to_vec(&snapshot).unwrap();
            let body = String::from_utf8(j).unwrap();

            if let Err(e) = socket.send(Message::Text(body.into())).await {
                debug!("send memory snapshot failed: {}", e);
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(
                interval.unwrap_or(1),
            ))
            .await;
        }
    })
}
