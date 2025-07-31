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

    #[allow(unused)]
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

#[allow(unused)]
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
                rule_payload: rule
                    .map(|x| x.payload().to_owned())
                    .unwrap_or_default(),
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

    pub fn trackers(
        &self,
    ) -> (
        Arc<dyn TrackCopy + Send + Sync>,
        Arc<dyn TrackCopy + Send + Sync>,
    ) {
        let r =
            Arc::new(ReadTracker::new(self.tracker.clone(), self.manager.clone()));
        let w = Arc::new(WriteTracker::new(
            self.tracker.clone(),
            self.manager.clone(),
        ));
        (r, w)
    }
}

#[allow(unused)]
pub trait TrackCopy {
    fn track(&self, total: usize);
}

impl TrackCopy for ReadTracker {
    fn track(&self, total: usize) {
        self.push_downloaded(total);
    }
}

impl TrackCopy for WriteTracker {
    fn track(&self, total: usize) {
        self.push_uploaded(total);
    }
}

#[allow(unused)]
pub struct ReadTracker {
    tracker: Arc<TrackerInfo>,
    manager: Arc<Manager>,
}

impl ReadTracker {
    fn new(tracker: Arc<TrackerInfo>, manager: Arc<Manager>) -> Self {
        Self { tracker, manager }
    }

    fn push_downloaded(&self, download: usize) {
        self.manager.push_downloaded(download);
        self.tracker
            .download_total
            .fetch_add(download as u64, std::sync::atomic::Ordering::Release);
    }
}

#[allow(unused)]
pub struct WriteTracker {
    tracker: Arc<TrackerInfo>,
    manager: Arc<Manager>,
}

impl WriteTracker {
    fn new(tracker: Arc<TrackerInfo>, manager: Arc<Manager>) -> Self {
        Self { tracker, manager }
    }

    fn push_uploaded(&self, upload: usize) {
        self.manager.push_uploaded(upload);
        self.tracker
            .upload_total
            .fetch_add(upload as u64, std::sync::atomic::Ordering::Release);
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
        match self.close_notify.try_recv() {
            Ok(_) => {
                debug!("connection closed by sig: {}", self.id());
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    debug!("connection closed drop: {}", self.id());
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        let v = Pin::new(self.inner.as_mut()).poll_read(cx, buf);
        let download = buf.filled().len();
        self.manager.push_downloaded(download);
        self.tracker
            .download_total
            .fetch_add(download as u64, std::sync::atomic::Ordering::Release);

        v
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        let v = Pin::new(self.inner.as_mut()).poll_write(cx, buf);
        let upload = match v {
            Poll::Ready(Ok(n)) => n,
            _ => return v,
        };
        self.manager.push_uploaded(upload);
        self.tracker
            .upload_total
            .fetch_add(upload as u64, std::sync::atomic::Ordering::Release);

        v
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        Pin::new(&mut self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
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
                rule_payload: rule
                    .map(|x| x.payload().to_owned())
                    .unwrap_or_default(),
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
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(None),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => return Poll::Ready(None),
            },
        }

        let r = Pin::new(self.inner.as_mut()).poll_next(cx);
        if let Poll::Ready(Some(ref pkt)) = r {
            self.manager.push_downloaded(pkt.data.len());
            self.tracker.download_total.fetch_add(
                pkt.data.len() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
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
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }
        Pin::new(self.inner.as_mut()).poll_ready(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        match self.close_notify.try_recv() {
            Ok(_) => return Err(std::io::ErrorKind::BrokenPipe.into()),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
            },
        }

        let upload = item.data.len();
        self.manager.push_uploaded(upload);
        self.tracker
            .upload_total
            .fetch_add(upload as u64, std::sync::atomic::Ordering::Relaxed);
        Pin::new(self.inner.as_mut()).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        Pin::new(self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        match self.close_notify.try_recv() {
            Ok(_) => return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(e) => match e {
                TryRecvError::Empty => {}
                TryRecvError::Closed => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
            },
        }

        Pin::new(self.inner.as_mut()).poll_close(cx)
    }
}
