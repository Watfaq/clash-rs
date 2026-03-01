use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
    routing::get,
};
use serde_json::json;
use tracing::{debug, warn};

use crate::app::api::{
        CtrlState,
        handlers::{
            connection::GetConnectionsQuery,
            memory::{GetMemoryQuery, GetMemoryResponse},
        },
    };

pub fn routes(state: Arc<CtrlState>) -> Router<Arc<CtrlState>> {
    Router::new()
        .route("/connections", get(connections))
        .route("/traffic", get(traffic))
        .route("/memory", get(memory))
        .route("/logs", get(log))
        .with_state(state)
}

pub async fn connections(
    ws: WebSocketUpgrade,
    State(state): State<Arc<CtrlState>>,
    query: Query<GetConnectionsQuery>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let interval = query.interval.unwrap_or(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval));

        loop {
            interval.tick().await;
            let snapshot = state.statistics_manager.snapshot().await;

            let body = serde_json::to_string(&snapshot)?;

            socket.send(Message::Text(body.into())).await?;
        }
        #[allow(unused)]
        anyhow::Ok(())
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await.unwrap_or_else(|e| {
            debug!("ws connection closed with error: {}", e);
        });
    })
}

pub async fn traffic(
    ws: WebSocketUpgrade,
    State(state): State<Arc<CtrlState>>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            interval.tick().await;
            let (up, down) = state.statistics_manager.now();
            let response = json!({
                "up": up,
                "down": down,
            })
            .to_string();
            socket.send(Message::Text(response.into())).await?;
        }
        #[allow(unused)]
        anyhow::Ok(())
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await.unwrap_or_else(|e| {
            debug!("ws connection closed with error: {}", e);
        });
    })
}

pub async fn memory(
    ws: WebSocketUpgrade,
    State(state): State<Arc<CtrlState>>,
    query: Query<GetMemoryQuery>,
) -> impl IntoResponse {
    let callback = async move |mut socket: WebSocket| {
        let interval = query.interval.unwrap_or(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval));

        loop {
            interval.tick().await;
            let snapshot = GetMemoryResponse {
                inuse: state.statistics_manager.memory_usage(),
                oslimit: 0,
            };

            let body = serde_json::to_string(&snapshot)?;

            socket.send(Message::Text(body.into())).await?;
        }
        #[allow(unused)]
        anyhow::Ok(())
    };
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(async move |socket| {
        callback(socket).await.unwrap_or_else(|e| {
            debug!("ws connection closed with error: {}", e);
        });
    })
}

pub async fn log(
    ws: WebSocketUpgrade,
    State(state): State<Arc<CtrlState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        let mut rx = state.log_source_tx.subscribe();
        while let Ok(evt) = rx.recv().await {
            let res = serde_json::to_vec(&evt).unwrap();

            if let Err(e) = socket
                .send(Message::Text(String::from_utf8(res).unwrap().into()))
                .await
            {
                warn!("ws send error: {}", e);
                break;
            }
        }
    })
}
