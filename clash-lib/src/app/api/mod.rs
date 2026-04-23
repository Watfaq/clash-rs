use std::sync::Arc;

use tokio::sync::broadcast::Sender;

use super::{dispatcher::StatisticsManager, logging::LogEvent};

mod handlers;
mod ipc;
mod middlewares;
mod runner;
mod websocket;

pub use runner::ApiRunner;

pub struct AppState {
    pub log_source_tx: Sender<LogEvent>,
    pub statistics_manager: Arc<StatisticsManager>,
}
