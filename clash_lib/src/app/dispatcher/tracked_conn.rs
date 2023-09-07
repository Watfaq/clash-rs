use std::{pin::Pin, sync::Arc, task::Poll};

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use crate::{config::internal::rule::RuleType, proxy::AnyStream, session::Session};

use super::statitics_manager::{Manager, TrackerInfo};

pub struct TrackedStream {
    inner: AnyStream,
    manager: Arc<Manager>,
    tracker: Arc<TrackerInfo>,
}

impl TrackedStream {
    pub async fn new(
        inner: AnyStream,
        manager: Arc<Manager>,
        sess: Session,
        rule: RuleType,
    ) -> Arc<Self> {
        let uuid = uuid::Uuid::new_v4();
        let s = Arc::new(Self {
            inner,
            manager: manager.clone(),
            tracker: Arc::new(TrackerInfo {
                uuid,
                session: sess,

                start_time: chrono::Utc::now(),
                rule: rule.to_string(),
                rule_payload: rule.target().to_owned(),
                ..Default::default()
            }),
        });

        manager.track(s.clone()).await;

        s
    }

    pub fn id(&self) -> uuid::Uuid {
        self.tracker.uuid
    }

    pub fn tracker_info(&self) -> Arc<TrackerInfo> {
        self.tracker.clone()
    }
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        debug!("untrack connection: {}", self.id());
        let _ = self.manager.untrack(self.id());
    }
}

impl AsyncRead for TrackedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let v = Pin::new(&mut self.inner).poll_read(cx, buf);
        let download = buf.filled().len();
        self.manager.push_downloaded(download);
        self.tracker
            .download_total
            .fetch_add(download as u64, std::sync::atomic::Ordering::Relaxed);
        v
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let v = Pin::new(&mut self.inner).poll_write(cx, buf);
        let upload = match v {
            Poll::Ready(Ok(n)) => n,
            _ => return v,
        };
        self.manager.push_uploaded(upload);
        self.tracker
            .upload_total
            .fetch_add(upload as u64, std::sync::atomic::Ordering::Relaxed);

        v
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
