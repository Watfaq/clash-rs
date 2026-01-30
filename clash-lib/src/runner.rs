use futures::future::BoxFuture;

pub trait Runner {
    /// Start running the runner in background.
    fn run(&mut self) -> BoxFuture<'_, Result<(), crate::Error>>;
    /// Signal the runner to shutdown.
    fn shutdown(&mut self) -> BoxFuture<'_, Result<(), crate::Error>>;
    /// Wait for the runner to finish.
    fn join(&mut self) -> BoxFuture<'_, Result<(), crate::Error>>;
}

pub type BoxedRunner = Box<dyn Runner + Send + Sync>;
