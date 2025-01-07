use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ws::Message, ConnectInfo, State, WebSocketUpgrade},
    response::IntoResponse,
};

use serde::Serialize;
use tracing::warn;

use crate::app::api::AppState;

#[derive(Serialize)]
struct TrafficResponse {
    up: i64,
    down: i64,
}
pub async fn handle(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {} with {}", e, addr);
    })
    .on_upgrade(move |mut socket| async move {
        let mgr = state.statistics_manager.clone();
        loop {
            let (up, down) = mgr.now();
            let res = TrafficResponse { up, down };
            let j = serde_json::to_vec(&res).unwrap();

            if let Err(e) = socket
                .send(Message::Text(String::from_utf8(j).unwrap().into()))
                .await
            {
                warn!("ws send error: {}", e);
                break;
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    })
}
