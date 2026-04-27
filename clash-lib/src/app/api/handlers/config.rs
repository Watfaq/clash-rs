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
        dns::{ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::{InboundEndpoint, InboundManager, Ports},
    },
    config::{def, internal::config::BindAddress},
};

#[derive(Serialize)]
struct DnsListenInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    udp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doh3: Option<String>,
}

#[derive(Clone)]
struct ConfigState {
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    dns_listen_addr: DNSListenAddr,
    dns_enabled: bool,
}

pub fn routes(
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    dns_listen_addr: DNSListenAddr,
    dns_enabled: bool,
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
            dns_listen_addr,
            dns_enabled,
        })
}

async fn get_configs(State(state): State<ConfigState>) -> impl IntoResponse {
    let run_mode = state.dispatcher.get_mode().await;
    let (log_level, config_path) = {
        let global_state = state.global_state.lock().await;
        (global_state.log_level, global_state.config_path.clone())
    };
    let inbound_manager = state.inbound_manager.clone();

    let ports = inbound_manager.get_ports().await;
    let allow_lan = inbound_manager.get_allow_lan().await;
    let listeners = inbound_manager.get_listeners().await;
    let bind_address = inbound_manager.get_bind_address().await.0.to_string();

    let lan_ips = if allow_lan {
        use network_interface::{NetworkInterface, NetworkInterfaceConfig};
        Some({
            let mut ips = NetworkInterface::show()
                .unwrap_or_default()
                .into_iter()
                .flat_map(|iface| {
                    iface.addr.into_iter().filter_map(|addr| match addr {
                        network_interface::Addr::V4(v4)
                            if !v4.ip.is_loopback() && !v4.ip.is_link_local() =>
                        {
                            Some(v4.ip.to_string())
                        }
                        _ => None,
                    })
                })
                .collect::<Vec<_>>();
            ips.sort();
            ips.dedup();
            ips
        })
    } else {
        None
    };

    let dns_listen = if state.dns_enabled {
        let addr = &state.dns_listen_addr;
        Some(DnsListenInfo {
            udp: addr.udp.map(|a| a.to_string()),
            tcp: addr.tcp.map(|a| a.to_string()),
            doh: addr.doh.as_ref().map(|c| c.addr.to_string()),
            dot: addr.dot.as_ref().map(|c| c.addr.to_string()),
            doh3: addr.doh3.as_ref().map(|c| c.addr.to_string()),
        })
    } else {
        None
    };

    axum::response::Json(GetConfigResponse {
        port: ports.port,
        socks_port: ports.socks_port,
        redir_port: ports.redir_port,
        tproxy_port: ports.tproxy_port,
        mixed_port: ports.mixed_port,
        bind_address: Some(bind_address),
        mode: Some(run_mode),
        log_level: Some(log_level),
        ipv6: Some(state.dns_resolver.ipv6()),
        allow_lan: Some(allow_lan),
        listeners: Some(listeners),
        lan_ips,
        dns_listen,
        config_path,
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
                    drop(g);
                    match wait.await {
                        Ok(_) => (StatusCode::NO_CONTENT, msg).into_response(),
                        Err(_) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "config reload failed",
                        )
                            .into_response(),
                    }
                }
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not signal config reload",
                )
                    .into_response(),
            }
        }
        // Empty string path means "reload from the original config file".
        (path, None) => {
            let resolved = match path.as_deref() {
                Some("") | None => {
                    // Use the path the binary was started with, if available.
                    match &g.config_path {
                        Some(p) => p.clone(),
                        None => {
                            return (
                                StatusCode::BAD_REQUEST,
                                "no config path provided and no original config \
                                 file known",
                            )
                                .into_response();
                        }
                    }
                }
                Some(p) => {
                    let mut resolved = p.to_string();
                    if !PathBuf::from(&resolved).is_absolute() {
                        resolved = PathBuf::from(g.cwd.clone())
                            .join(resolved)
                            .to_string_lossy()
                            .to_string();
                    }
                    resolved
                }
            };

            if !PathBuf::from(&resolved).exists() {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("config file {resolved} not found"),
                )
                    .into_response();
            }
            if !PathBuf::from(&resolved).is_file() {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("{resolved} is not a file"),
                )
                    .into_response();
            }

            let msg = format!("config reloading from file {resolved}");
            let cfg: crate::Config = crate::Config::File(resolved);
            match g.reload_tx.send((cfg, done)).await {
                Ok(_) => {
                    drop(g);
                    match wait.await {
                        Ok(_) => (StatusCode::NO_CONTENT, msg).into_response(),
                        Err(_) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "config reload failed",
                        )
                            .into_response(),
                    }
                }
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not signal config reload",
                )
                    .into_response(),
            }
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct GetConfigResponse {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    listeners: Option<Vec<InboundEndpoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lan_ips: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_listen: Option<DnsListenInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_path: Option<String>,
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

    let mut port_changed = false;
    if payload.rebuild_listeners() {
        let ports = Ports {
            port: payload.port,
            socks_port: payload.socks_port,
            redir_port: payload.redir_port,
            tproxy_port: payload.tproxy_port,
            mixed_port: payload.mixed_port,
        };
        port_changed = inbound_manager.change_ports(ports).await;
        need_restart |= port_changed;
    }

    if let Some(allow_lan) = payload.allow_lan
        && allow_lan != inbound_manager.get_allow_lan().await
    {
        inbound_manager.set_allow_lan(allow_lan).await;
        // TODO: can be done with AtomicBool in each inbound manager, but requires
        // more changes
        need_restart = true;
        port_changed = false; // force full restart
    }

    // Apply mode change before restarting listeners so that new connections
    // established after the restart immediately use the updated mode.
    if let Some(mode) = payload.mode {
        state.dispatcher.set_mode(mode).await;
    }

    if need_restart {
        if port_changed {
            // Port-only change: restart only the affected listener(s).
            // Unchanged listeners keep running — no EADDRINUSE.
            let _ = inbound_manager.restart_idle().await;
        } else {
            let _ = inbound_manager.restart().await;
        }
    }

    if let Some(ipv6) = payload.ipv6 {
        state.dns_resolver.set_ipv6(ipv6);
    }

    // Only lock global_state for the small section that actually needs it.
    // Holding it across inbound_manager.restart() (which can be slow) was
    // blocking concurrent GET /configs requests unnecessarily.
    if let Some(log_level) = payload.log_level {
        let mut global_state = state.global_state.lock().await;
        global_state.log_level = log_level;
    }

    StatusCode::ACCEPTED.into_response()
}
