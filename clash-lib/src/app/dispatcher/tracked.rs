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

#[async_trait]
pub trait ChainedStream: ProxyStream + Downcast {
    fn chain(&self) -> &ProxyChain;
    async fn append_to_chain(&self, name: &str);

    /// The underlying OS socket, if this stream is a direct single-hop
    /// passthrough over a raw `TcpStream`. Used by the splice/zero-copy path.
    /// Returns `None` for any stream with a transform above the socket.
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut tokio::net::TcpStream> {
        self.as_any_mut()
            .downcast_mut::<ChainedStreamWrapper<tokio::net::TcpStream>>()
            .map(|w| w.inner_mut())
    }
}
impl_downcast!(ChainedStream);

pub type BoxedChainedStream = Box<dyn ChainedStream>;

pub struct ChainedStreamWrapper<T> {
    inner: T,
    chain: ProxyChain,
}

impl<T> ChainedStreamWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            chain: ProxyChain::default(),
        }
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

#[async_trait]
impl<T> ChainedStream for ChainedStreamWrapper<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    fn chain(&self) -> &ProxyChain {
        &self.chain
    }

    async fn append_to_chain(&self, name: &str) {
        self.chain.push(name.to_owned()).await;
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
        Pin::new(&mut self.inner).poll_read(cx, buf)
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
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct TrackedStream {
    inner: BoxedChainedStream,
    manager: Arc<Manager>,
    tracker: Arc<TrackerInfo>,
    close_notify: Receiver<()>,
}

impl TrackedStream {
    #[allow(clippy::borrowed_box)]
    pub async fn new(
        inner: BoxedChainedStream,
        manager: Arc<Manager>,
        sess: Session,
        rule: Option<&Box<dyn RuleMatcher>>,
    ) -> Self {
        let uuid = uuid::Uuid::new_v4();
        let chain = inner.chain().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let s = Self {
            inner,
            manager: manager.clone(),
            tracker: Arc::new(TrackerInfo {
                uuid,
                session_holder: sess,

                start_time: chrono::Utc::now(),
                rule: rule
                    .as_ref()
                    .map(|x| x.type_name().to_owned())
                    .unwrap_or_default(),
                rule_payload: rule.map(|x| x.payload()).unwrap_or_default(),
                proxy_chain_holder: chain.clone(),
                ..Default::default()
            }),
            close_notify: rx,
        };

        manager.track(Tracked(uuid, s.tracker_info()), tx).await;

        s
    }

    fn id(&self) -> uuid::Uuid {
        self.tracker.uuid
    }

    pub fn tracker_info(&self) -> Arc<TrackerInfo> {
        self.tracker.clone()
    }

    pub fn inner_mut(&mut self) -> &mut BoxedChainedStream {
        &mut self.inner
    }

    fn poll_closed(&mut self) -> Option<std::io::Error> {
        match self.close_notify.try_recv() {
            Ok(_) | Err(TryRecvError::Closed) => {
                debug!("connection closed: {}", self.id());
                Some(std::io::ErrorKind::BrokenPipe.into())
            }
            Err(TryRecvError::Empty) => None,
        }
    }

    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    pub fn trackers(
        &self,
    ) -> (
        Arc<dyn TrackCopy + Send + Sync>,
        Arc<dyn TrackCopy + Send + Sync>,
    ) {
        let r = Arc::new(DirCopy {
            tracker: self.tracker.clone(),
            manager: self.manager.clone(),
            download: true,
        });
        let w = Arc::new(DirCopy {
            tracker: self.tracker.clone(),
            manager: self.manager.clone(),
            download: false,
        });
        (r, w)
    }
}

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

impl Drop for TrackedStream {
    fn drop(&mut self) {
        debug!("untrack connection: {}", self.id());
        self.manager.untrack(self.id());
    }
}

impl AsyncRead for TrackedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(e) = self.poll_closed() {
            return Poll::Ready(Err(e));
        }

        let v = Pin::new(self.inner.as_mut()).poll_read(cx, buf);
        let download = buf.filled().len();
        self.tracker.account_download(&self.manager, download);
        v
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if let Some(e) = self.poll_closed() {
            return Poll::Ready(Err(e));
        }

        let v = Pin::new(self.inner.as_mut()).poll_write(cx, buf);
        let upload = match v {
            Poll::Ready(Ok(n)) => n,
            _ => return v,
        };
        self.tracker.account_upload(&self.manager, upload);
        v
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if let Some(e) = self.poll_closed() {
            return Poll::Ready(Err(e));
        }

        Pin::new(&mut self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if let Some(e) = self.poll_closed() {
            return Poll::Ready(Err(e));
        }

        Pin::new(self.inner.as_mut()).poll_shutdown(cx)
    }
}

#[async_trait]
pub trait ChainedDatagram:
    Stream<Item = UdpPacket> + Sink<UdpPacket, Error = std::io::Error> + Unpin
{
    fn chain(&self) -> &ProxyChain;
    async fn append_to_chain(&self, name: &str);
}

pub type BoxedChainedDatagram = Box<dyn ChainedDatagram + Send + Sync>;

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
}

#[derive(Debug)]
pub struct ChainedDatagramWrapper<T> {
    inner: T,
    chain: ProxyChain,
}

impl<T> ChainedDatagramWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            chain: ProxyChain::default(),
        }
    }
}

impl<T> Stream for ChainedDatagramWrapper<T>
where
    T: Stream<Item = UdpPacket> + Unpin,
{
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }
}
impl<T> Sink<UdpPacket> for ChainedDatagramWrapper<T>
where
    T: Sink<UdpPacket, Error = std::io::Error> + Unpin,
{
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        Pin::new(&mut self.get_mut().inner).start_send(item)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

pub struct TrackedDatagram {
    inner: BoxedChainedDatagram,
    manager: Arc<Manager>,
    tracker: Arc<TrackerInfo>,
    close_notify: Receiver<()>,
}

impl TrackedDatagram {
    #[allow(clippy::borrowed_box)]
    pub async fn new(
        inner: BoxedChainedDatagram,
        manager: Arc<Manager>,
        sess: Session,
        rule: Option<&Box<dyn RuleMatcher>>,
    ) -> Self {
        let uuid = uuid::Uuid::new_v4();
        let chain = inner.chain().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let s = Self {
            inner,
            manager: manager.clone(),
            tracker: Arc::new(TrackerInfo {
                uuid,
                session_holder: sess,

                start_time: chrono::Utc::now(),
                rule: rule
                    .as_ref()
                    .map(|x| x.type_name().to_owned())
                    .unwrap_or_default(),
                rule_payload: rule.map(|x| x.payload()).unwrap_or_default(),
                proxy_chain_holder: chain.clone(),
                ..Default::default()
            }),
            close_notify: rx,
        };

        manager.track(Tracked(uuid, s.tracker_info()), tx).await;

        s
    }

    pub fn id(&self) -> uuid::Uuid {
        self.tracker.uuid
    }

    pub fn tracker_info(&self) -> Arc<TrackerInfo> {
        self.tracker.clone()
    }

    fn poll_closed(&mut self) -> Option<std::io::Error> {
        match self.close_notify.try_recv() {
            Ok(_) | Err(TryRecvError::Closed) => {
                debug!("connection closed: {}", self.id());
                Some(std::io::ErrorKind::BrokenPipe.into())
            }
            Err(TryRecvError::Empty) => None,
        }
    }
}

impl Drop for TrackedDatagram {
    fn drop(&mut self) {
        debug!("untrack connection: {}", self.id());
        self.manager.untrack(self.id());
    }
}

impl Stream for TrackedDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        // poll_next returns None (not an error) on close — keep this inline.
        match self.close_notify.try_recv() {
            Ok(_) | Err(TryRecvError::Closed) => return Poll::Ready(None),
            Err(TryRecvError::Empty) => {}
        }

        let r = Pin::new(self.inner.as_mut()).poll_next(cx);
        if let Poll::Ready(Some(ref pkt)) = r {
            let n = pkt.data.len();
            self.tracker.account_download(&self.manager, n);
        }
        r
    }
}

impl Sink<UdpPacket> for TrackedDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(e) = self.poll_closed() {
            return Poll::Ready(Err(e));
        }
        Pin::new(self.inner.as_mut()).poll_ready(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        if let Some(e) = self.poll_closed() {
            return Err(e);
        }

        let upload = item.data.len();
        self.tracker.account_upload(&self.manager, upload);
        Pin::new(self.inner.as_mut()).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(e) = self.poll_closed() {
            return Poll::Ready(Err(e));
        }

        Pin::new(self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if let Some(e) = self.poll_closed() {
            return Poll::Ready(Err(e));
        }

        Pin::new(self.inner.as_mut()).poll_close(cx)
    }
}
