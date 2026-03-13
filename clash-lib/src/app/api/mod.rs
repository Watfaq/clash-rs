use std::sync::Arc;

use tokio::sync::broadcast::Sender;

use super::{dispatcher::StatisticsManager, logging::LogEvent};

mod handlers;
mod ipc;
mod middlewares;
mod runner;

pub use runner::ApiRunner;

pub struct AppState {
    log_source_tx: Sender<LogEvent>,
    statistics_manager: Arc<StatisticsManager>,
}
