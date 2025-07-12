use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{
        FromRequest, Path, Query, Request, State, WebSocketUpgrade, ws::Message,
    },
    response::IntoResponse,
    routing::{delete, get},
};
use http::HeaderMap;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::app::{
    api::{AppState, handlers::utils::is_request_websocket},
    dispatcher::StatisticsManager,
};

#[derive(Clone)]
struct ConnectionState {
    statistics_manager: Arc<StatisticsManager>,
}

pub fn routes(statistics_manager: Arc<StatisticsManager>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_connections).delete(close_all_connection))
        .route("/{id}", delete(close_connection))
        .with_state(ConnectionState { statistics_manager })
}

#[derive(Deserialize)]
struct GetConnectionsQuery {
    interval: Option<u64>,
}

async fn get_connections(
    headers: HeaderMap,
    State(state): State<ConnectionState>,
    q: Query<GetConnectionsQuery>,
    req: Request<Body>,
) -> impl IntoResponse {
    if !is_request_websocket(headers) {
        let mgr = state.statistics_manager.clone();
        let snapshot = mgr.snapshot().await;
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
            let snapshot = mgr.snapshot().await;
            let j = serde_json::to_vec(&snapshot).unwrap();
            let body = String::from_utf8(j).unwrap();

            if let Err(e) = socket.send(Message::Text(body.into())).await {
                // likely client gone
                debug!("ws send error: {}", e);
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(
                interval.unwrap_or(1),
            ))
            .await;
        }
    })
}

async fn close_connection(
    State(state): State<ConnectionState>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    let mgr = state.statistics_manager;
    mgr.close(id).await;
    format!("connection {id} closed").into_response()
}

async fn close_all_connection(
    State(state): State<ConnectionState>,
) -> impl IntoResponse {
    let mgr = state.statistics_manager;
    mgr.close_all().await;
    "all connections closed".into_response()
}
