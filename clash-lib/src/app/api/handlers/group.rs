use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::Request,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};

use http::StatusCode;
use serde::Deserialize;
use tracing::instrument;

use crate::{
    app::{api::AppState, outbound::manager::ThreadSafeOutboundManager},
    proxy::AnyOutboundHandler,
};

#[derive(Clone)]
pub struct GroupState {
    outbound_manager: ThreadSafeOutboundManager,
}

pub fn routes(outbound_manager: ThreadSafeOutboundManager) -> Router<Arc<AppState>> {
    let state = GroupState { outbound_manager };
    Router::new()
        .nest(
            "/{name}",
            Router::new()
                .route("/delay", get(get_group_delay))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    find_group_by_name,
                ))
                .with_state(state.clone()),
        )
        .with_state(state)
}

async fn find_group_by_name(
    State(state): State<GroupState>,
    Path(name): Path<String>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let outbound_manager = state.outbound_manager.clone();
    match outbound_manager.get_outbound(&name) {
        Some(proxy) => {
            req.extensions_mut().insert(proxy);
            next.run(req).await
        }
        _ => (StatusCode::NOT_FOUND, format!("group {name} not found"))
            .into_response(),
    }
}

#[derive(Deserialize)]
struct DelayRequest {
    url: String,
    timeout: u16,
}

#[instrument(skip_all, fields(name = %proxy.name()))]
async fn get_group_delay(
    State(state): State<GroupState>,
    Extension(proxy): Extension<AnyOutboundHandler>,
    Query(q): Query<DelayRequest>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let timeout = Duration::from_millis(q.timeout.into());

    if let Some(group) = proxy.try_as_group_handler() {
        let latency_test_url = group.get_latency_test_url();
        let proxies = group.get_proxies().await;
        let names = proxies
            .iter()
            .map(|p| p.name().to_owned())
            .collect::<Vec<_>>();
        let results = outbound_manager
            .url_test(
                &[vec![proxy], proxies].concat(),
                &latency_test_url.unwrap_or(q.url),
                timeout,
            )
            .await;

        let mut res = HashMap::new();

        for i in 0..names.len() {
            let p = &names[i];
            if let Some(Ok(latency)) = results.get(i) {
                res.insert(p.to_owned(), latency.0.as_millis());
            } else {
                res.insert(p.to_owned(), 0);
            }
        }
        Json(res).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            format!("proxy {} is not a group", proxy.name()),
        )
            .into_response()
    }
}
