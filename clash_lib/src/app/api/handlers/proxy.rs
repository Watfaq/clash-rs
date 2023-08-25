use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

use crate::app::{api::AppState, outbound::manager::ThreadSafeOutboundManager};

#[derive(Clone)]
pub struct ProxyState {
    outbound_manager: ThreadSafeOutboundManager,
}

pub fn routes(outbound_manager: ThreadSafeOutboundManager) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_proxies))
        .with_state(ProxyState { outbound_manager })
}

async fn get_proxies(State(state): State<ProxyState>) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.read().await;
    let mut res = HashMap::new();
    let proxies = outbound_manager.get_proxies().await;
    res.insert("proxies".to_owned(), proxies);
    axum::response::Json(res)
}
