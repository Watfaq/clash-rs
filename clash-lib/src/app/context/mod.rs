
use tokio_util::sync::CancellationToken;

/// Application context that provides global state and cancellation signals
/// to all components in the system.
#[derive(Clone, Debug)]
pub struct AppContext {
    pub shutdown_token: CancellationToken,
    // Future additions (e.g., config, global log level) can be placed here
}

impl AppContext {
    /// Create a new application context with an empty cancellation token.
    pub fn new() -> Self {
        Self {
            shutdown_token: CancellationToken::new(),
        }
    }

    /// Create an application context bounded to an existing cancellation token.
    pub fn with_token(token: CancellationToken) -> Self {
        Self {
            shutdown_token: token,
        }
    }

    /// Check if a shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown_token.is_cancelled()
    }

    /// Request a shutdown for all components using this context.
    pub fn shutdown(&self) {
        self.shutdown_token.cancel();
    }
}

impl Default for AppContext {
    fn default() -> Self {
        Self::new()
    }
}
