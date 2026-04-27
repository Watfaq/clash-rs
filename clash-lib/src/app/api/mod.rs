use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use tokio::sync::broadcast::Sender;

use super::{dispatcher::StatisticsManager, logging::LogEvent};

#[cfg(feature = "dashboard")]
mod embedded_dashboard;
mod handlers;
mod ipc;
mod middlewares;
mod runner;
mod tcp;
mod websocket;

pub use runner::ApiRunner;

pub struct AppState {
    pub log_source_tx: Sender<LogEvent>,
    pub statistics_manager: Arc<StatisticsManager>,
    /// Ring buffer of recent log events — replayed to new WS clients on
    /// connect.
    pub recent_logs: Arc<Mutex<VecDeque<LogEvent>>>,
}
