use std::{fmt::Debug, pin::Pin, sync::Arc, task::Poll};

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
// Internal tracking state — installed by the dispatcher on the outermost box
// ---------------------------------------------------------------------------

struct StreamTracking {
    manager: Arc<Manager>,
    tracker: Arc<TrackerInfo>,
    close_notify: Receiver<()>,
}

struct DatagramTracking {
    manager: Arc<Manager>,
    tracker: Arc<TrackerInfo>,
    close_notify: Receiver<()>,
}

// ---------------------------------------------------------------------------
// ChainedStream trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait ChainedStream: ProxyStream + Sync + Downcast {
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
            .downcast_mut::<ChainedStreamWrapper<tokio::net::TcpStream>>()
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
impl_downcast!(ChainedStream);

pub type BoxedChainedStream = Box<dyn ChainedStream>;

impl crate::proxy::ProxyStream for Box<dyn ChainedStream> {
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut tokio::net::TcpStream> {
        ChainedStream::underlying_socket(self.as_mut())
    }
}

// ---------------------------------------------------------------------------
// ChainedStreamWrapper — the single stream wrapper
// ---------------------------------------------------------------------------

pub struct ChainedStreamWrapper<T> {
    inner: T,
    chain: ProxyChain,
    tracking: Option<StreamTracking>,
}

impl<T> ChainedStreamWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            chain: ProxyChain::default(),
            tracking: None,
        }
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    fn poll_closed(tracking: &mut StreamTracking) -> Option<std::io::Error> {
        match tracking.close_notify.try_recv() {
            Ok(_) | Err(TryRecvError::Closed) => {
                debug!("connection closed: {}", tracking.tracker.uuid);
                Some(std::io::ErrorKind::BrokenPipe.into())
            }
            Err(TryRecvError::Empty) => None,
        }
    }
}

#[async_trait]
impl<T> ChainedStream for ChainedStreamWrapper<T>
where
    T: crate::proxy::ProxyStream + AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    fn chain(&self) -> &ProxyChain {
        &self.chain
    }

    async fn append_to_chain(&self, name: &str) {
        self.chain.push(name.to_owned()).await;
    }

    #[allow(clippy::borrowed_box)]
    async fn install_tracking(
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
        self.tracking = Some(StreamTracking {
            manager,
            tracker,
            close_notify: rx,
        });
    }

    fn tracker_info(&self) -> Option<Arc<TrackerInfo>> {
        self.tracking.as_ref().map(|t| t.tracker.clone())
    }

    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn trackers(
        &self,
    ) -> Option<(
        Arc<dyn TrackCopy + Send + Sync>,
        Arc<dyn TrackCopy + Send + Sync>,
    )> {
        self.tracking.as_ref().map(|t| {
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

impl<T> Drop for ChainedStreamWrapper<T> {
    fn drop(&mut self) {
        if let Some(t) = &self.tracking {
            debug!("untrack connection: {}", t.tracker.uuid);
            t.manager.untrack(t.tracker.uuid);
        }
    }
}

impl<T> AsyncRead for ChainedStreamWrapper<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(t) = &mut self.tracking
            && let Some(e) = Self::poll_closed(t)
        {
            return Poll::Ready(Err(e));
        }

        let v = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Some(t) = &self.tracking {
            let download = buf.filled().len();
            t.tracker.account_download(&t.manager, download);
        }
        v
    }
}

impl<T> AsyncWrite for ChainedStreamWrapper<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if let Some(t) = &mut self.tracking
            && let Some(e) = Self::poll_closed(t)
        {
            return Poll::Ready(Err(e));
        }

        let v = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &v
            && let Some(t) = &self.tracking
        {
            t.tracker.account_upload(&t.manager, *n);
        }
        v
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if let Some(t) = &mut self.tracking
            && let Some(e) = Self::poll_closed(t)
        {
            return Poll::Ready(Err(e));
        }

        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if let Some(t) = &mut self.tracking
            && let Some(e) = Self::poll_closed(t)
        {
            return Poll::Ready(Err(e));
        }

        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// ProxyStream impl for ChainedStreamWrapper
// ---------------------------------------------------------------------------

impl<T> crate::proxy::ProxyStream for ChainedStreamWrapper<T>
where
    T: crate::proxy::ProxyStream + AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
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
// ChainedDatagram trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait ChainedDatagram:
    Stream<Item = UdpPacket> + Sink<UdpPacket, Error = std::io::Error> + Unpin
{
    fn chain(&self) -> &ProxyChain;
    async fn append_to_chain(&self, name: &str);

    /// Install byte-accounting / close-notify tracking on this datagram wrapper.
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

pub type BoxedChainedDatagram = Box<dyn ChainedDatagram + Send + Sync>;

// ---------------------------------------------------------------------------
// ChainedDatagramWrapper — the single datagram wrapper
// ---------------------------------------------------------------------------

pub struct ChainedDatagramWrapper<T> {
    inner: T,
    chain: ProxyChain,
    tracking: Option<DatagramTracking>,
}

impl<T: Debug> Debug for ChainedDatagramWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainedDatagramWrapper")
            .field("inner", &self.inner)
            .field("chain", &self.chain)
            .finish()
    }
}

impl<T> ChainedDatagramWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            chain: ProxyChain::default(),
            tracking: None,
        }
    }

    fn poll_closed(tracking: &mut DatagramTracking) -> Option<std::io::Error> {
        match tracking.close_notify.try_recv() {
            Ok(_) | Err(TryRecvError::Closed) => {
                debug!("connection closed: {}", tracking.tracker.uuid);
                Some(std::io::ErrorKind::BrokenPipe.into())
            }
            Err(TryRecvError::Empty) => None,
        }
    }
}

#[async_trait]
impl<T> ChainedDatagram for ChainedDatagramWrapper<T>
where
    T: Sink<UdpPacket, Error = std::io::Error> + Unpin + Send + Sync + 'static,
    T: Stream<Item = UdpPacket>,
{
    fn chain(&self) -> &ProxyChain {
        &self.chain
    }

    async fn append_to_chain(&self, name: &str) {
        self.chain.push(name.to_owned()).await;
    }

    #[allow(clippy::borrowed_box)]
    async fn install_tracking(
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
        self.tracking = Some(DatagramTracking {
            manager,
            tracker,
            close_notify: rx,
        });
    }

    fn tracker_info(&self) -> Option<Arc<TrackerInfo>> {
        self.tracking.as_ref().map(|t| t.tracker.clone())
    }
}

impl<T> Drop for ChainedDatagramWrapper<T> {
    fn drop(&mut self) {
        if let Some(t) = &self.tracking {
            debug!("untrack connection: {}", t.tracker.uuid);
            t.manager.untrack(t.tracker.uuid);
        }
    }
}

impl<T> Stream for ChainedDatagramWrapper<T>
where
    T: Stream<Item = UdpPacket> + Unpin,
{
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        // poll_next returns None (not an error) on close — keep inline.
        if let Some(t) = &mut self.tracking {
            match t.close_notify.try_recv() {
                Ok(_) | Err(TryRecvError::Closed) => return Poll::Ready(None),
                Err(TryRecvError::Empty) => {}
            }
        }

        let r = Pin::new(&mut self.inner).poll_next(cx);
        if let Poll::Ready(Some(ref pkt)) = r
            && let Some(t) = &self.tracking
        {
            t.tracker.account_download(&t.manager, pkt.data.len());
        }
        r
    }
}

impl<T> Sink<UdpPacket> for ChainedDatagramWrapper<T>
where
    T: Sink<UdpPacket, Error = std::io::Error> + Unpin,
{
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(t) = &mut self.tracking
            && let Some(e) = Self::poll_closed(t)
        {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        if let Some(t) = &mut self.tracking {
            if let Some(e) = Self::poll_closed(t) {
                return Err(e);
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
        if let Some(t) = &mut self.tracking
            && let Some(e) = Self::poll_closed(t)
        {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(t) = &mut self.tracking
            && let Some(e) = Self::poll_closed(t)
        {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
