use std::sync::Arc;

use axum::{response::IntoResponse, routing::get, Router};
use http::StatusCode;

use crate::app::{api::AppState, dns::ThreadSafeDNSResolver};

#[derive(Clone)]
struct DNSState {
    #[allow(dead_code)]
    resolver: ThreadSafeDNSResolver,
}

pub fn routes(resolver: ThreadSafeDNSResolver) -> Router<Arc<AppState>> {
    let state = DNSState { resolver };
    Router::new()
        .route("/dns", get(query_dns))
        .with_state(state)
}

async fn query_dns() -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
}
