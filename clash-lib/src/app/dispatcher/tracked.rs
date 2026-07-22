use std::{fmt::Debug, future::Future, pin::Pin, sync::Arc, task::Poll};

use async_trait::async_trait;
use downcast_rs::{Downcast, impl_downcast};
use futures::{Sink, Stream};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::oneshot::{Receiver, error::TryRecvError},
};
use tracing::debug;

use crate::{
    app::router::RuleMatcher,
    proxy::{ProxyStream, datagram::UdpPacket},
    session::Session,
};

use super::statistics_manager::{Manager, ProxyChain, TrackerInfo};

pub struct Tracked(uuid::Uuid, Arc<TrackerInfo>);

impl Tracked {
    pub fn id(&self) -> uuid::Uuid {
        self.0
    }

    pub fn tracker_info(&self) -> Arc<TrackerInfo> {
        self.1.clone()
    }
}

// ---------------------------------------------------------------------------
// Shared instrumentation — proxy-chain metadata + optional byte/close tracking.
// Embedded by both the stream and datagram wrappers; the only difference
// between TCP and UDP is the I/O trait impls, not this bookkeeping.
// ---------------------------------------------------------------------------

struct Tracking {
    manager: Arc<Manager>,
    tracker: Arc<TrackerInfo>,
    close_notify: Receiver<()>,
}

struct Instrumentation {
    chain: ProxyChain,
    tracking: Option<Tracking>,
}

impl Instrumentation {
    fn new() -> Self {
        Self {
            chain: ProxyChain::default(),
            tracking: None,
        }
    }

    async fn append_to_chain(&self, name: &str) {
        self.chain.push(name.to_owned()).await;
    }

    #[allow(clippy::borrowed_box)]
    async fn install(
        &mut self,
        manager: Arc<Manager>,
        sess: Session,
        rule: Option<&Box<dyn RuleMatcher>>,
    ) {
        let uuid = uuid::Uuid::new_v4();
        let chain = self.chain.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let tracker = Arc::new(TrackerInfo {
            uuid,
            session_holder: sess,
            start_time: chrono::Utc::now(),
            rule: rule
                .as_ref()
                .map(|x| x.type_name().to_owned())
                .unwrap_or_default(),
            rule_payload: rule.map(|x| x.payload()).unwrap_or_default(),
            proxy_chain_holder: chain,
            ..Default::default()
        });
        manager.track(Tracked(uuid, tracker.clone()), tx).await;
        self.tracking = Some(Tracking {
            manager,
            tracker,
            close_notify: rx,
        });
    }

    fn tracker_info(&self) -> Option<Arc<TrackerInfo>> {
        self.tracking.as_ref().map(|t| t.tracker.clone())
    }

    /// Poll the close-notify channel, registering the task waker so an idle
    /// connection wakes when `Manager::close` fires. Returns `Some(err)` when
    /// the connection should be treated as closed, `None` while still open.
    fn poll_closed(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Option<std::io::Error> {
        let t = self.tracking.as_mut()?;
        match Pin::new(&mut t.close_notify).poll(cx) {
            Poll::Ready(_) => {
                debug!("connection closed: {}", t.tracker.uuid);
                Some(std::io::ErrorKind::BrokenPipe.into())
            }
            Poll::Pending => None,
        }
    }
}

impl Drop for Instrumentation {
    fn drop(&mut self) {
        if let Some(t) = &self.tracking {
            debug!("untrack connection: {}", t.tracker.uuid);
            t.manager.untrack(t.tracker.uuid);
        }
    }
}

// ---------------------------------------------------------------------------
// InstrumentedStream trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait InstrumentedStream: ProxyStream + Sync + Downcast {
    fn chain(&self) -> &ProxyChain;
    async fn append_to_chain(&self, name: &str);

    /// Install byte-accounting / close-notify tracking on this wrapper.
    /// Called exactly once by the dispatcher on the outermost box.
    #[allow(clippy::borrowed_box)]
    async fn install_tracking(
        &mut self,
        manager: Arc<Manager>,
        sess: Session,
        rule: Option<&Box<dyn RuleMatcher>>,
    );

    /// Return the tracker info if tracking has been installed.
    fn tracker_info(&self) -> Option<Arc<TrackerInfo>>;

    /// The underlying OS socket, if this stream is a direct single-hop
    /// passthrough over a raw `TcpStream`. Used by the splice/zero-copy path.
    /// Returns `None` for any stream with a transform above the socket.
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut tokio::net::TcpStream> {
        self.as_any_mut()
            .downcast_mut::<InstrumentedStreamWrapper<tokio::net::TcpStream>>()
            .map(|w| w.inner_mut())
    }

    /// Return tracker handles for the splice/zero-copy path.
    /// Returns `None` when tracking is not installed (inner hops).
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn trackers(
        &self,
    ) -> Option<(
        Arc<dyn TrackCopy + Send + Sync>,
        Arc<dyn TrackCopy + Send + Sync>,
    )> {
        None
    }
}
impl_downcast!(InstrumentedStream);

pub type BoxedInstrumentedStream = Box<dyn InstrumentedStream>;

impl crate::proxy::ProxyStream for Box<dyn InstrumentedStream> {
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut tokio::net::TcpStream> {
        InstrumentedStream::underlying_socket(self.as_mut())
    }
}

// ---------------------------------------------------------------------------
// InstrumentedStreamWrapper — the single stream wrapper
// ---------------------------------------------------------------------------

pub struct InstrumentedStreamWrapper<T> {
    inner: T,
    inst: Instrumentation,
}

impl<T> InstrumentedStreamWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            inst: Instrumentation::new(),
        }
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

#[async_trait]
impl<T> InstrumentedStream for InstrumentedStreamWrapper<T>
where
    T: crate::proxy::ProxyStream
        + AsyncRead
        + AsyncWrite
        + Unpin
        + Send
        + Sync
        + 'static,
{
    fn chain(&self) -> &ProxyChain {
        &self.inst.chain
    }

    async fn append_to_chain(&self, name: &str) {
        self.inst.append_to_chain(name).await;
    }

    #[allow(clippy::borrowed_box)]
    async fn install_tracking(
        &mut self,
        manager: Arc<Manager>,
        sess: Session,
        rule: Option<&Box<dyn RuleMatcher>>,
    ) {
        self.inst.install(manager, sess, rule).await;
    }

    fn tracker_info(&self) -> Option<Arc<TrackerInfo>> {
        self.inst.tracker_info()
    }

    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn trackers(
        &self,
    ) -> Option<(
        Arc<dyn TrackCopy + Send + Sync>,
        Arc<dyn TrackCopy + Send + Sync>,
    )> {
        self.inst.tracking.as_ref().map(|t| {
            let r: Arc<dyn TrackCopy + Send + Sync> = Arc::new(DirCopy {
                tracker: t.tracker.clone(),
                manager: t.manager.clone(),
                download: true,
            });
            let w: Arc<dyn TrackCopy + Send + Sync> = Arc::new(DirCopy {
                tracker: t.tracker.clone(),
                manager: t.manager.clone(),
                download: false,
            });
            (r, w)
        })
    }
}

impl<T> AsyncRead for InstrumentedStreamWrapper<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(e) = self.inst.poll_closed(cx) {
            return Poll::Ready(Err(e));
        }

        let before = buf.filled().len();
        let v = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &v
            && let Some(t) = &self.inst.tracking
        {
            let download = buf.filled().len() - before;
            t.tracker.account_download(&t.manager, download);
        }
        v
    }
}

impl<T> AsyncWrite for InstrumentedStreamWrapper<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if let Some(e) = self.inst.poll_closed(cx) {
            return Poll::Ready(Err(e));
        }

        let v = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &v
            && let Some(t) = &self.inst.tracking
        {
            t.tracker.account_upload(&t.manager, *n);
        }
        v
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if let Some(e) = self.inst.poll_closed(cx) {
            return Poll::Ready(Err(e));
        }

        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if let Some(e) = self.inst.poll_closed(cx) {
            return Poll::Ready(Err(e));
        }

        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// ProxyStream impl for InstrumentedStreamWrapper
// ---------------------------------------------------------------------------

impl<T> crate::proxy::ProxyStream for InstrumentedStreamWrapper<T>
where
    T: crate::proxy::ProxyStream
        + AsyncRead
        + AsyncWrite
        + Unpin
        + Send
        + Sync
        + 'static,
{
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut tokio::net::TcpStream> {
        self.inner.underlying_socket()
    }
}

// ---------------------------------------------------------------------------
// Zero-copy helpers (Linux only)
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
pub trait TrackCopy {
    fn track(&self, total: usize);
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
pub struct DirCopy {
    tracker: Arc<TrackerInfo>,
    manager: Arc<Manager>,
    download: bool,
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
impl TrackCopy for DirCopy {
    fn track(&self, n: usize) {
        if self.download {
            self.tracker.account_download(&self.manager, n);
        } else {
            self.tracker.account_upload(&self.manager, n);
        }
    }
}

// ---------------------------------------------------------------------------
// InstrumentedDatagram trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait InstrumentedDatagram:
    Stream<Item = UdpPacket> + Sink<UdpPacket, Error = std::io::Error> + Unpin
{
    fn chain(&self) -> &ProxyChain;
    async fn append_to_chain(&self, name: &str);

    /// Install byte-accounting / close-notify tracking on this datagram
    /// wrapper.
    #[allow(clippy::borrowed_box)]
    async fn install_tracking(
        &mut self,
        manager: Arc<Manager>,
        sess: Session,
        rule: Option<&Box<dyn RuleMatcher>>,
    );

    /// Return the tracker info if tracking has been installed.
    fn tracker_info(&self) -> Option<Arc<TrackerInfo>>;
}

pub type BoxedInstrumentedDatagram = Box<dyn InstrumentedDatagram + Send + Sync>;

// ---------------------------------------------------------------------------
// InstrumentedDatagramWrapper — the single datagram wrapper
// ---------------------------------------------------------------------------

pub struct InstrumentedDatagramWrapper<T> {
    inner: T,
    inst: Instrumentation,
}

impl<T: Debug> Debug for InstrumentedDatagramWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstrumentedDatagramWrapper")
            .field("inner", &self.inner)
            .field("chain", &self.inst.chain)
            .finish()
    }
}

impl<T> InstrumentedDatagramWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            inst: Instrumentation::new(),
        }
    }
}

#[async_trait]
impl<T> InstrumentedDatagram for InstrumentedDatagramWrapper<T>
where
    T: Sink<UdpPacket, Error = std::io::Error> + Unpin + Send + Sync + 'static,
    T: Stream<Item = UdpPacket>,
{
    fn chain(&self) -> &ProxyChain {
        &self.inst.chain
    }

    async fn append_to_chain(&self, name: &str) {
        self.inst.append_to_chain(name).await;
    }

    #[allow(clippy::borrowed_box)]
    async fn install_tracking(
        &mut self,
        manager: Arc<Manager>,
        sess: Session,
        rule: Option<&Box<dyn RuleMatcher>>,
    ) {
        self.inst.install(manager, sess, rule).await;
    }

    fn tracker_info(&self) -> Option<Arc<TrackerInfo>> {
        self.inst.tracker_info()
    }
}

impl<T> Stream for InstrumentedDatagramWrapper<T>
where
    T: Stream<Item = UdpPacket> + Unpin,
{
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        // poll_next returns None (not an error) on close. Poll (not try_recv)
        // so the task waker is registered and an idle receiver wakes on close.
        if let Some(t) = &mut self.inst.tracking
            && Pin::new(&mut t.close_notify).poll(cx).is_ready()
        {
            return Poll::Ready(None);
        }

        let r = Pin::new(&mut self.inner).poll_next(cx);
        if let Poll::Ready(Some(ref pkt)) = r
            && let Some(t) = &self.inst.tracking
        {
            t.tracker.account_download(&t.manager, pkt.data.len());
        }
        r
    }
}

impl<T> Sink<UdpPacket> for InstrumentedDatagramWrapper<T>
where
    T: Sink<UdpPacket, Error = std::io::Error> + Unpin,
{
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(e) = self.inst.poll_closed(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        if let Some(t) = &mut self.inst.tracking {
            // No task context here; a plain try_recv is the best we can do.
            // Readiness/close wakeups are handled by poll_ready/poll_flush.
            if matches!(t.close_notify.try_recv(), Ok(_) | Err(TryRecvError::Closed))
            {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            let upload = item.data.len();
            t.tracker.account_upload(&t.manager, upload);
        }
        Pin::new(&mut self.inner).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(e) = self.inst.poll_closed(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(e) = self.inst.poll_closed(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
