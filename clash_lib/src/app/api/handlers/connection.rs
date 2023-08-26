use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ws::Message, ConnectInfo, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Router,
};
use tracing::{debug, warn};

use crate::app::api::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/", get(get_connections))
}

async fn get_connections(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    debug!("ws connect from {}", addr);
    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        if let Err(e) = socket
            .send(Message::Text("not implemented".to_owned()))
            .await
        {
            warn!("ws send error: {}", e);
        }
        _ = socket.close().await;
    })
}
