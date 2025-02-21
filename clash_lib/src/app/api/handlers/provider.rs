use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use serde::Deserialize;

use crate::{
    app::{
        api::AppState, outbound::manager::ThreadSafeOutboundManager,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    proxy::AnyOutboundHandler,
};
#[derive(Clone)]
struct ProviderState {
    outbound_manager: ThreadSafeOutboundManager,
}

pub fn routes(outbound_manager: ThreadSafeOutboundManager) -> Router<Arc<AppState>> {
    let state = ProviderState { outbound_manager };
    Router::new()
        .route("/", get(get_providers))
        .nest(
            "/{provider_name}",
            Router::new()
                .route("/", get(get_provider).put(update_provider))
                .route("/healthcheck", get(provider_healthcheck))
                .nest(
                    "/{proxy_name}",
                    Router::new()
                        .route("/", get(get_proxy))
                        .route("/healthcheck", get(get_proxy_delay))
                        .layer(middleware::from_fn_with_state(
                            state.clone(),
                            find_provider_proxy_by_name,
                        ))
                        .with_state(state.clone()),
                )
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    find_proxy_provider_by_name,
                ))
                .with_state(state.clone()),
        )
        .with_state(state)
}

async fn get_providers(State(state): State<ProviderState>) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let mut res = HashMap::new();

    let mut providers = HashMap::new();

    for (name, p) in outbound_manager.get_proxy_providers() {
        let p = p.read().await;
        let proxies = p.proxies().await;
        let proxies = futures::future::join_all(
            proxies.iter().map(|x| outbound_manager.get_proxy(x)),
        );
        let mut m = p.as_map().await;
        m.insert("proxies".to_owned(), Box::new(proxies.await));
        providers.insert(name, m);
    }

    res.insert("providers".to_owned(), providers);
    axum::response::Json(res)
}

async fn find_proxy_provider_by_name(
    State(state): State<ProviderState>,
    Path(name): Path<String>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let outbound_manager = state.outbound_manager.clone();
    match outbound_manager.get_proxy_provider(&name) { Some(provider) => {
        req.extensions_mut().insert(provider);
        next.run(req).await
    } _ => {
        (
            StatusCode::NOT_FOUND,
            format!("proxy provider {} not found", name),
        )
            .into_response()
    }}
}

async fn get_provider(
    Extension(provider): Extension<ThreadSafeProxyProvider>,
) -> impl IntoResponse {
    let provider = provider.read().await;
    axum::response::Json(provider.as_map().await)
}

async fn update_provider(
    Extension(provider): Extension<ThreadSafeProxyProvider>,
) -> impl IntoResponse {
    let provider = provider.read().await;
    match provider.update().await {
        Ok(_) => (StatusCode::ACCEPTED, "provider update started").into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "update proxy provider {} failed with error {}",
                provider.name(),
                err
            ),
        )
            .into_response(),
    }
}

async fn provider_healthcheck(
    Extension(provider): Extension<ThreadSafeProxyProvider>,
) -> impl IntoResponse {
    let provider = provider.read().await;
    provider.healthcheck().await;

    (StatusCode::ACCEPTED, "provider healthcheck")
}

async fn find_provider_proxy_by_name(
    Extension(provider): Extension<ThreadSafeProxyProvider>,
    Path(params): Path<HashMap<String, String>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let proxy = provider.read().await.proxies().await;
    let proxy = proxy
        .iter()
        .find(|x| Some(&x.name().to_string()) == params.get("proxy_name"));

    if let Some(proxy) = proxy {
        req.extensions_mut().insert(proxy.clone());
        next.run(req).await
    } else {
        (
            StatusCode::NOT_FOUND,
            format!(
                "proxy {} not found in provider {}",
                params.get("proxy_name").unwrap(),
                provider.read().await.name()
            ),
        )
            .into_response()
    }
}

async fn get_proxy(
    Extension(proxy): Extension<AnyOutboundHandler>,
    State(state): State<ProviderState>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    axum::response::Json(outbound_manager.get_proxy(&proxy).await)
}

#[derive(Deserialize)]
struct DelayRequest {
    url: String,
    timeout: u16,
}
async fn get_proxy_delay(
    State(state): State<ProviderState>,
    Extension(proxy): Extension<AnyOutboundHandler>,
    Query(q): Query<DelayRequest>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let timeout = Duration::from_millis(q.timeout.into());
    let n = proxy.name().to_owned();
    match outbound_manager.url_test(proxy, &q.url, timeout).await {
        Ok((delay, mean_delay)) => {
            let mut r = HashMap::new();
            r.insert("delay".to_owned(), delay);
            r.insert("meanDelay".to_owned(), mean_delay);
            axum::response::Json(delay).into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            format!("get delay for {} failed with error: {}", n, err),
        )
            .into_response(),
    }
}
