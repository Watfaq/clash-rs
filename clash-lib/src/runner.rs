use futures::future::BoxFuture;

pub trait Runner: Send + Sync {
    /// Start running the runner in background.
    fn run(&self) -> BoxFuture<'_, Result<(), crate::Error>>;
    /// Signal the runner to shutdown.
    fn shutdown(&self) -> BoxFuture<'_, Result<(), crate::Error>>;
    /// Wait for the runner to finish.
    fn join(&self) -> BoxFuture<'_, Result<(), crate::Error>>;
}
