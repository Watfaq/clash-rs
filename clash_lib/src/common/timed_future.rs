use std::{pin::Pin, time::Duration};

use futures::Future;
use tokio::time::Instant;

pub struct TimedFuture<Fut: Future + Unpin> {
    fut: Fut,
    started_at: Option<Instant>,
}

impl<Fut: Future + Unpin> TimedFuture<Fut> {
    pub fn new(fut: Fut, started_at: Option<Instant>) -> Self {
        Self { fut, started_at }
    }
}

impl<Fut: Future + Unpin> Future for TimedFuture<Fut> {
    type Output = (Fut::Output, Duration);

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let Self { fut, started_at } = self.get_mut();
        let started_at = started_at.get_or_insert_with(Instant::now);
        let output = futures::ready!(Pin::new(fut).poll(cx));
        let elapsed = started_at.elapsed();
        std::task::Poll::Ready((output, elapsed))
    }
}
