use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::warn;

use crate::{
    app::{
        api::AppState,
        dispatcher,
        inbound::manager::{Ports, ThreadSafeInboundManager},
        ThreadSafeDNSResolver,
    },
    config::{def, internal::config::BindAddress},
    GlobalState,
};

#[derive(Clone)]
struct ConfigState {
    inbound_manager: ThreadSafeInboundManager,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
}

pub fn routes(
    inbound_manager: ThreadSafeInboundManager,
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
    let inbound_manager = state.inbound_manager.lock().await;
    let run_mode = state.dispatcher.get_mode().await;
    let global_state = state.global_state.lock().await;
    let dns_resolver = state.dns_resolver;

    let ports = inbound_manager.get_ports();

    axum::response::Json(ConfigRequest {
        port: ports.port,
        socks_port: ports.socks_port,
        redir_port: ports.redir_port,
        tproxy_port: ports.tproxy_port,
        mixed_port: ports.mixed_port,
        bind_address: Some(inbound_manager.get_bind_address().to_string()),

        mode: Some(run_mode),
        log_level: Some(global_state.log_level),
        ipv6: Some(dns_resolver.ipv6()),
        allow_lan: Some(match inbound_manager.get_bind_address() {
            BindAddress::Any => true,
            BindAddress::One(one) => match one {
                crate::proxy::utils::Interface::IpAddr(ip) => !ip.is_loopback(),
                crate::proxy::utils::Interface::Name(iface) => iface != "lo",
            },
        }),
    })
}

async fn update_configs() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        axum::response::Json("don't do this please"),
    )
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ConfigRequest {
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

impl ConfigRequest {
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
    Json(payload): Json<ConfigRequest>,
) -> impl IntoResponse {
    if payload.allow_lan.is_some() {
        warn!("setting allow_lan doesn't do anything. please set bind_address to a LAN address instead.");
    }

    let mut inbound_manager = state.inbound_manager.lock().await;

    if let Some(bind_address) = payload.bind_address.clone() {
        match bind_address.parse::<BindAddress>() {
            Ok(bind_address) => {
                inbound_manager.set_bind_address(bind_address);
            }
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid bind address: {}", bind_address),
                )
                    .into_response();
            }
        }
    }

    let mut global_state = state.global_state.lock().await;

    if payload.rebuild_listeners() {
        // TODO: maybe buggy
        let current_ports = inbound_manager.get_ports();

        let ports = Ports {
            port: payload.port.or(current_ports.port),
            socks_port: payload.socks_port.or(current_ports.socks_port),
            redir_port: payload.redir_port.or(current_ports.redir_port),
            tproxy_port: payload.tproxy_port.or(current_ports.tproxy_port),
            mixed_port: payload.mixed_port.or(current_ports.mixed_port),
        };

        inbound_manager.rebuild_listeners(ports);

        global_state
            .inbound_listener_handle
            .take()
            .map(|h| h.abort());

        let r = inbound_manager.get_runner().unwrap();

        global_state.inbound_listener_handle = Some(tokio::spawn(r));
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
