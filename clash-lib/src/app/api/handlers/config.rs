use std::{path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};

use http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    GlobalState,
    app::{
        api::AppState,
        dispatcher,
        dns::ThreadSafeDNSResolver,
        inbound::manager::{InboundManager, Ports},
    },
    config::{def, internal::config::BindAddress},
};

#[derive(Clone)]
struct ConfigState {
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
}

pub fn routes(
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/",
            get(get_configs).put(update_configs).patch(patch_configs),
        )
        .with_state(ConfigState {
            inbound_manager,
            dispatcher,
            global_state,
            dns_resolver,
        })
}

async fn get_configs(State(state): State<ConfigState>) -> impl IntoResponse {
    let run_mode = state.dispatcher.get_mode().await;
    let global_state = state.global_state.lock().await;
    let dns_resolver = state.dns_resolver;
    let inbound_manager = state.inbound_manager.clone();

    let ports = state.inbound_manager.get_ports().await;

    axum::response::Json(PatchConfigRequest {
        port: ports.port,
        socks_port: ports.socks_port,
        redir_port: ports.redir_port,
        tproxy_port: ports.tproxy_port,
        mixed_port: ports.mixed_port,
        bind_address: Some(
            state.inbound_manager.get_bind_address().await.0.to_string(),
        ),

        mode: Some(run_mode),
        log_level: Some(global_state.log_level),
        ipv6: Some(dns_resolver.ipv6()),
        allow_lan: Some(inbound_manager.get_allow_lan().await),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct UpdateConfigRequest {
    path: Option<String>,
    payload: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct UploadConfigQuery {
    force: Option<bool>,
}

async fn update_configs(
    _q: Query<UploadConfigQuery>,
    State(state): State<ConfigState>,
    Json(req): Json<UpdateConfigRequest>,
) -> impl IntoResponse {
    let (done, wait) = tokio::sync::oneshot::channel();
    let g = state.global_state.lock().await;
    match (req.path, req.payload) {
        (_, Some(payload)) => {
            let msg = "config reloading from payload".to_string();
            let cfg = crate::Config::Str(payload);
            match g.reload_tx.send((cfg, done)).await {
                Ok(_) => {
                    wait.await.unwrap();
                    (StatusCode::NO_CONTENT, msg).into_response()
                }
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not signal config reload",
                )
                    .into_response(),
            }
        }
        (Some(mut path), None) => {
            if !PathBuf::from(&path).is_absolute() {
                path = PathBuf::from(g.cwd.clone())
                    .join(path)
                    .to_string_lossy()
                    .to_string();
            }
            if !PathBuf::from(&path).exists() {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("config file {path} not found"),
                )
                    .into_response();
            }

            let msg = format!("config reloading from file {path}");
            let cfg: crate::Config = crate::Config::File(path);
            match g.reload_tx.send((cfg, done)).await {
                Ok(_) => {
                    wait.await.unwrap();
                    (StatusCode::NO_CONTENT, msg).into_response()
                }

                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not signal config reload",
                )
                    .into_response(),
            }
        }
        (None, None) => {
            (StatusCode::BAD_REQUEST, "no path or payload provided").into_response()
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct PatchConfigRequest {
    port: Option<u16>,
    socks_port: Option<u16>,
    redir_port: Option<u16>,
    tproxy_port: Option<u16>,
    mixed_port: Option<u16>,
    bind_address: Option<String>,
    mode: Option<def::RunMode>,
    log_level: Option<def::LogLevel>,
    ipv6: Option<bool>,
    allow_lan: Option<bool>,
}

impl PatchConfigRequest {
    fn rebuild_listeners(&self) -> bool {
        self.port.is_some()
            || self.socks_port.is_some()
            || self.redir_port.is_some()
            || self.tproxy_port.is_some()
            || self.mixed_port.is_some()
            || self.bind_address.is_some()
    }
}

async fn patch_configs(
    State(state): State<ConfigState>,
    Json(payload): Json<PatchConfigRequest>,
) -> impl IntoResponse {
    let inbound_manager = state.inbound_manager.clone();
    let mut need_restart = false;
    if let Some(bind_address) = payload.bind_address.clone() {
        match bind_address.parse::<BindAddress>() {
            Ok(bind_address) => {
                inbound_manager.set_bind_address(bind_address).await;
                need_restart = true;
            }
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid bind address: {bind_address}"),
                )
                    .into_response();
            }
        }
    }

    let mut global_state = state.global_state.lock().await;

    if payload.rebuild_listeners() {
        let ports = Ports {
            port: payload.port,
            socks_port: payload.socks_port,
            redir_port: payload.redir_port,
            tproxy_port: payload.tproxy_port,
            mixed_port: payload.mixed_port,
        };
        inbound_manager.change_ports(ports).await;
        need_restart = true;
    }

    if let Some(allow_lan) = payload.allow_lan
        && allow_lan != inbound_manager.get_allow_lan().await
    {
        inbound_manager.set_allow_lan(allow_lan).await;
        // TODO: can be done with AtomicBool, but requires more changes
        need_restart = true;
    }

    if need_restart {
        inbound_manager.restart().await;
    }

    if let Some(mode) = payload.mode {
        state.dispatcher.set_mode(mode).await;
    }

    if let Some(log_level) = payload.log_level {
        global_state.log_level = log_level;
    }

    if let Some(ipv6) = payload.ipv6 {
        state.dns_resolver.set_ipv6(ipv6);
    }

    StatusCode::ACCEPTED.into_response()
}
