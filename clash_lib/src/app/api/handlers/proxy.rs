use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    extract::{Extension, Path, Query, State},
    http::Request,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};

use http::{header, HeaderMap, StatusCode};
use serde::Deserialize;

use crate::{
    app::{
        api::AppState, outbound::manager::ThreadSafeOutboundManager, profile::ThreadSafeCacheFile,
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
            "/:name",
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
    if let Some(proxy) = outbound_manager.get_outbound(&name) {
        req.extensions_mut().insert(proxy);
        next.run(req).await
    } else {
        (StatusCode::NOT_FOUND, format!("proxy {} not found", name)).into_response()
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
    if let Some(ctrl) = outbound_manager.get_selector_control(proxy.name()) {
        match ctrl.lock().await.select(&payload.name).await {
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
        }
    } else {
        (
            StatusCode::NOT_FOUND,
            format!("proxy {} is not a Select", proxy.name()),
        )
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
    match outbound_manager.url_test(proxy, &q.url, timeout).await {
        Ok((delay, mean_delay)) => {
            let mut r = HashMap::new();
            r.insert("delay".to_owned(), delay);
            r.insert("meanDelay".to_owned(), mean_delay);
            (headers, axum::response::Json(r)).into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            headers,
            format!("get delay for {} failed with error: {}", n, err),
        )
            .into_response(),
    }
}
