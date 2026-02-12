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

use std::future::Future;
use tokio::task::{JoinHandle, spawn as tokio_spawn};
use tokio_util::sync::CancellationToken;

#[inline(always)]
pub fn spawn<F, Fut>(token: CancellationToken, future: F) -> JoinHandle<()>
where
    F: FnOnce(CancellationToken) -> Fut + Send + 'static,
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    let fut = future(token.child_token());
    tokio_spawn(async move {
        tokio::select! {
            _ = token.cancelled() => {
                // Task was cancelled, return early
                // We can do some cleanup here if needed before
                return;
            }
            output = fut => {
                // future completed, do something with the output if needed
                // I perfer to use a Result or ControlFlow enum here to indicate success or failure instead of panicking
                // Such as: ControlFlow::Continue(()) or ControlFlow::Break(error)
                // We can cancel ourself if it's an error, or just log it and return if it's a success
                // if output.is_break() {
                    // token.cancel();
                // }

                _ = output; // Ignore the output for now
            }
        }
    })
}

pub async fn how_to_use() {
    let token = CancellationToken::new();
    spawn(token.child_token(), long_time_polling);

    spawn(token.child_token(), async move |token| {
        _ = token; // Use the token if needed, or just ignore it if not

        // Simulate some work in the background task
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    })
    .await
    .unwrap();

    // Simulate some work in the main task
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    // Signal tasks to shutdown
    token.cancel();
}

pub async fn long_time_polling(token: CancellationToken) {
    struct StateMaybeIO;
    impl StateMaybeIO {
        async fn close(&mut self) {
            // Simulate some cleanup work here
            // For TUIC we need send `FIN` to the peer before close the connection,
            // so we can do that here Or close all UdpSesions
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    // Simulate a long-running task that checks for cancellation

    let mut state = StateMaybeIO;
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                // Task was cancelled, perform cleanup and return
                state.close().await;
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                // Do some work here...
            }
        }
    }
}
