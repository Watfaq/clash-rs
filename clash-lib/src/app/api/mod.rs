use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router, middleware,
    response::Redirect,
    routing::{get, post},
};
use http::{Method, header};
use tokio::sync::{Mutex, broadcast::Sender};
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{error, info, warn};

use crate::{GlobalState, Runner, config::internal::config::Controller};

use super::{
    dispatcher::{self, StatisticsManager},
    dns::ThreadSafeDNSResolver,
    inbound::manager::InboundManager,
    logging::LogEvent,
    outbound::manager::ThreadSafeOutboundManager,
    profile::ThreadSafeCacheFile,
    router::ThreadSafeRouter,
};

mod handlers;
mod ipc;
mod middlewares;
mod runner;

pub use runner::ApiRunner;

pub struct AppState {
    log_source_tx: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
}
