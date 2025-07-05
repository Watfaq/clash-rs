use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::Request,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};

use http::{HeaderMap, StatusCode, header};
use serde::Deserialize;

use crate::{
    app::{
        api::AppState, outbound::manager::ThreadSafeOutboundManager,
        profile::ThreadSafeCacheFile,
    },
    proxy::AnyOutboundHandler,
};

#[derive(Clone)]
pub struct ProxyState {
    outbound_manager: ThreadSafeOutboundManager,
    cache_store: ThreadSafeCacheFile,
}

pub fn routes(
    outbound_manager: ThreadSafeOutboundManager,
    cache_store: ThreadSafeCacheFile,
) -> Router<Arc<AppState>> {
    let state = ProxyState {
        outbound_manager,
        cache_store,
    };
    Router::new()
        .route("/", get(get_proxies))
        .nest(
            "/{name}",
            Router::new()
                .route("/", get(get_proxy).put(update_proxy))
                .route("/delay", get(get_proxy_delay))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    find_proxy_by_name,
                ))
                .with_state(state.clone()),
        )
        .with_state(state)
}

async fn get_proxies(State(state): State<ProxyState>) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let mut res = HashMap::new();
    let proxies = outbound_manager.get_proxies().await;
    res.insert("proxies".to_owned(), proxies);
    axum::response::Json(res)
}

async fn find_proxy_by_name(
    State(state): State<ProxyState>,
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
        _ => (StatusCode::NOT_FOUND, format!("proxy {} not found", name))
            .into_response(),
    }
}

async fn get_proxy(
    Extension(proxy): Extension<AnyOutboundHandler>,
    State(state): State<ProxyState>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    axum::response::Json(outbound_manager.get_proxy(&proxy).await)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct UpdateProxyRequest {
    name: String,
}

async fn update_proxy(
    State(state): State<ProxyState>,
    Extension(proxy): Extension<AnyOutboundHandler>,
    Json(payload): Json<UpdateProxyRequest>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    match outbound_manager.get_selector_control(proxy.name()) {
        Some(ctrl) => match ctrl.lock().await.select(&payload.name).await {
            Ok(_) => {
                let cache_store = state.cache_store;
                cache_store.set_selected(proxy.name(), &payload.name).await;
                (
                    StatusCode::ACCEPTED,
                    format!("selected proxy {} for {}", payload.name, proxy.name()),
                )
            }
            Err(err) => (
                StatusCode::BAD_REQUEST,
                format!(
                    "select {} for {} failed with error: {}",
                    payload.name,
                    proxy.name(),
                    err
                ),
            ),
        },
        _ => (
            StatusCode::NOT_FOUND,
            format!("proxy {} is not a Select", proxy.name()),
        ),
    }
}

#[derive(Deserialize)]
struct DelayRequest {
    url: String,
    timeout: u16,
}
async fn get_proxy_delay(
    State(state): State<ProxyState>,
    Extension(proxy): Extension<AnyOutboundHandler>,
    Query(q): Query<DelayRequest>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let timeout = Duration::from_millis(q.timeout.into());
    let n = proxy.name().to_owned();
    let mut headers = HeaderMap::new();
    headers.insert(header::CONNECTION, "close".parse().unwrap());

    let (delay, mean_delay) = if let Some(group) = proxy.try_as_group_handler() {
        let latency_test_url = group.get_latency_test_url();
        let proxies = group.get_proxies().await;
        let results = outbound_manager
            .url_test(
                &[vec![proxy], proxies].concat(),
                &latency_test_url.unwrap_or(q.url),
                timeout,
            )
            .await;
        match results.first().unwrap() {
            Ok(latency) => latency.clone(),
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    headers,
                    format!("get delay for {} failed with error: {}", n, err),
                )
                    .into_response();
            }
        }
    } else {
        let result = outbound_manager
            .url_test(&vec![proxy], &q.url, timeout)
            .await;
        match result.first().unwrap() {
            Ok(latency) => latency.clone(),
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    headers,
                    format!("get delay for {} failed with error: {}", n, err),
                )
                    .into_response();
            }
        }
    };

    let mut r = HashMap::new();
    r.insert("delay".to_owned(), delay);
    r.insert("meanDelay".to_owned(), mean_delay);
    (headers, axum::response::Json(r)).into_response()
}
