use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ws::Message, ConnectInfo, State, WebSocketUpgrade},
    response::IntoResponse,
};

use tracing::{debug, warn};

use crate::app::api::AppState;

pub async fn handle(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    debug!("ws connect from {}", addr);
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        let mut rx = state.log_source_tx.subscribe();
        while let Ok(evt) = rx.recv().await {
            // TODO: if I'd need to do 1 more of this I'd def pull serde-json |
            let res = vec![
                "{\"type\": \"",
                match evt.level {
                    crate::config::def::LogLevel::Debug => "debug",
                    crate::config::def::LogLevel::Info => "info",
                    crate::config::def::LogLevel::Warning => "warning",
                    crate::config::def::LogLevel::Error => "error",
                    crate::config::def::LogLevel::Silent => "slient",
                },
                "\", \"payload\": \"",
                evt.msg.as_str(),
                "\"}",
            ];
            if let Err(e) = socket.send(Message::Text(res.concat())).await {
                warn!("ws send error: {}", e);
                break;
            }
        }
    })
}
