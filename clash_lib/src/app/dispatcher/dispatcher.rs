use crate::app::dispatcher::tracked::TrackedDatagram;
use crate::app::dispatcher::tracked::TrackedStream;
use crate::app::outbound::manager::ThreadSafeOutboundManager;
use crate::app::router::ThreadSafeRouter;
use crate::common::io::copy_buf_bidirectional_with_timeout;
use crate::config::def::RunMode;
use crate::config::internal::proxy::PROXY_DIRECT;
use crate::config::internal::proxy::PROXY_GLOBAL;
use crate::proxy::datagram::UdpPacket;
use crate::proxy::AnyInboundDatagram;
use crate::session::Session;
use arc_swap::ArcSwap;
use futures::SinkExt;
use futures::StreamExt;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::info_span;
use tracing::instrument;
use tracing::trace;
use tracing::Instrument;
use tracing::{debug, error, info, warn};

use crate::app::dns::ThreadSafeDNSResolver;

use super::statistics_manager::Manager;

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ThreadSafeRouter,
    resolver: ThreadSafeDNSResolver,
    mode: ArcSwap<RunMode>,

    manager: Arc<Manager>,
}

impl Debug for Dispatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher").finish()
    }
}

impl Dispatcher {
    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        router: ThreadSafeRouter,
        resolver: ThreadSafeDNSResolver,
        mode: RunMode,

        statistics_manager: Arc<Manager>,
    ) -> Self {
        Self {
            outbound_manager,
            router,
            resolver,
            mode: Arc::new(mode).into(),
            manager: statistics_manager,
        }
    }

    pub async fn set_mode(&self, mode: RunMode) {
        info!("run mode switched to {}", mode);

        self.mode.store(Arc::new(mode));
    }

    pub async fn get_mode(&self) -> RunMode {
        **self.mode.load()
    }

    #[instrument(skip(lhs))]
    pub async fn dispatch_stream<S>(&self, sess: Session, mut lhs: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let sess = if self.resolver.fake_ip_enabled() {
            match sess.destination {
                crate::session::SocksAddr::Ip(addr) => {
                    let ip = addr.ip();
                    if self.resolver.is_fake_ip(ip).await {
                        let host = self.resolver.reverse_lookup(ip).await;
                        match host {
                            Some(host) => {
                                let mut sess = sess;
                                sess.destination =
                                    crate::session::SocksAddr::Domain(host, addr.port());
                                sess
                            }
                            None => {
                                error!("failed to reverse lookup fake ip: {}", ip);
                                return;
                            }
                        }
                    } else {
                        sess
                    }
                }
                crate::session::SocksAddr::Domain(_, _) => sess,
            }
        } else {
            sess
        };

        let mode = **self.mode.load();
        debug!("dispatching {} with mode {}", sess, mode);
        let (outbound_name, rule) = match mode {
            RunMode::Global => (PROXY_GLOBAL, None),
            RunMode::Rule => self.router.match_route(&sess).await,
            RunMode::Direct => (PROXY_DIRECT, None),
        };

        let mgr = self.outbound_manager.clone();
        let handler = mgr.get_outbound(outbound_name).unwrap_or_else(|| {
            debug!("unknown rule: {}, fallback to direct", outbound_name);
            mgr.get_outbound(PROXY_DIRECT).unwrap()
        });

        match handler
            .connect_stream(&sess, self.resolver.clone())
            .instrument(info_span!(
                "connect_stream",
                outbound_name = outbound_name,
                session = %sess,
            ))
            .await
        {
            Ok(rhs) => {
                debug!("remote connection established {}", sess);
                let mut rhs =
                    TrackedStream::new(rhs, self.manager.clone(), sess.clone(), rule).await;
                match copy_buf_bidirectional_with_timeout(
                    &mut lhs,
                    &mut rhs,
                    4096,
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                )
                .instrument(info_span!(
                    "copy_bidirectional",
                    outbound_name = outbound_name,
                    session = %sess,
                ))
                .await
                {
                    Ok((up, down)) => {
                        debug!(
                            "connection {} closed with {} bytes up, {} bytes down",
                            sess, up, down
                        );
                    }
                    Err(err) => match err.kind() {
                        std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe => {
                            debug!("connection {} closed with error {}", sess, err);
                        }
                        _ => {
                            warn!("connection {} closed with error {}", sess, err);
                        }
                    },
                }
            }
            Err(err) => {
                warn!(
                    "failed to establish remote connection {}, error: {}",
                    sess, err
                );
                if let Err(e) = lhs.shutdown().await {
                    warn!("error closing local connection {}: {}", sess, e)
                }
            }
        }
    }

    /// Dispatch a UDP packet to outbound handler
    /// returns the close sender
    #[instrument]
    pub fn dispatch_datagram(
        &self,
        sess: Session,
        udp_inbound: AnyInboundDatagram,
    ) -> tokio::sync::oneshot::Sender<u8> {
        let outbound_handle_guard = TimeoutUdpSessionManager::new();

        let router = self.router.clone();
        let outbound_manager = self.outbound_manager.clone();
        let resolver = self.resolver.clone();
        let mode = **self.mode.load();
        let manager = self.manager.clone();

        let (mut local_w, mut local_r) = udp_inbound.split();
        let (remote_receiver_w, mut remote_receiver_r) = tokio::sync::mpsc::channel(32);

        let s = sess.clone();
        let ss = sess.clone();
        let t1 = tokio::spawn(async move {
            while let Some(packet) = local_r.next().await {
                let mut sess = sess.clone();
                sess.source = packet.src_addr.clone().must_into_socket_addr();
                sess.destination = packet.dst_addr.clone();

                // populate fake ip for route matching
                let sess = if resolver.fake_ip_enabled() {
                    trace!("fake ip enabled");
                    match sess.destination {
                        crate::session::SocksAddr::Ip(addr) => {
                            let ip = addr.ip();
                            if resolver.is_fake_ip(ip).await {
                                trace!("fake ip detected");
                                let host = resolver.reverse_lookup(ip).await;
                                match host {
                                    Some(host) => {
                                        trace!("fake ip resolved to {}", host);
                                        let mut sess = sess;
                                        sess.destination =
                                            crate::session::SocksAddr::Domain(host, addr.port());
                                        sess
                                    }
                                    None => {
                                        error!("failed to reverse lookup fake ip: {}", ip);
                                        return;
                                    }
                                }
                            } else {
                                sess
                            }
                        }
                        crate::session::SocksAddr::Domain(_, _) => sess,
                    }
                } else {
                    sess
                };

                // mutate packet for fake ip
                let mut packet = packet;
                packet.dst_addr = sess.destination.clone();

                let mode = mode.clone();
                trace!("dispatching {} with mode {}", sess, mode);

                let (outbound_name, rule) = match mode {
                    RunMode::Global => (PROXY_GLOBAL, None),
                    RunMode::Rule => router.match_route(&sess).await,
                    RunMode::Direct => (PROXY_DIRECT, None),
                };
                let outbound_name = outbound_name.to_string();
                debug!("dispatching {} to {}", sess, outbound_name);

                let remote_receiver_w = remote_receiver_w.clone();

                let mgr = outbound_manager.clone();
                let handler = mgr.get_outbound(&outbound_name).unwrap_or_else(|| {
                    debug!("unknown rule: {}, fallback to direct", outbound_name);
                    mgr.get_outbound(PROXY_DIRECT).unwrap()
                });

                match outbound_handle_guard
                    .get_outbound_sender_mut(
                        &outbound_name,
                        packet.src_addr.clone().must_into_socket_addr(), // this is only expected to be socket addr as it's from local udp
                    )
                    .await
                {
                    None => {
                        debug!("building {} outbound datagram connecting", sess);
                        let outbound_datagram =
                            match handler.connect_datagram(&sess, resolver.clone()).await {
                                Ok(v) => v,
                                Err(err) => {
                                    error!("failed to connect outbound: {}", err);
                                    return;
                                }
                            };

                        debug!("{} outbound datagram connected", sess);

                        let outbound_datagram = TrackedDatagram::new(
                            outbound_datagram,
                            manager.clone(),
                            sess.clone(),
                            rule,
                        )
                        .await;

                        let (mut remote_w, mut remote_r) = outbound_datagram.split();
                        let (remote_sender, mut remote_forwarder) =
                            tokio::sync::mpsc::channel::<UdpPacket>(32);

                        // remote -> local
                        let r_handle = tokio::spawn(async move {
                            while let Some(packet) = remote_r.next().await {
                                // NAT
                                let mut packet = packet;
                                packet.src_addr = sess.destination.clone().into();
                                packet.dst_addr = sess.source.into();

                                debug!("UDP NAT for packet: {:?}, session: {}", packet, sess);
                                match remote_receiver_w.send(packet).await {
                                    Ok(_) => {}
                                    Err(err) => {
                                        warn!("failed to send packet to local: {}", err);
                                    }
                                }
                            }
                        });
                        // local -> remote
                        let w_handle = tokio::spawn(async move {
                            while let Some(packet) = remote_forwarder.recv().await {
                                match remote_w.send(packet.clone()).await {
                                    Ok(_) => {
                                        debug!("{} sent to remote", packet);
                                    }
                                    Err(err) => {
                                        warn!("failed to send packet to remote: {}", err);
                                    }
                                }
                            }
                        });

                        outbound_handle_guard
                            .insert(
                                &outbound_name,
                                packet.src_addr.clone().must_into_socket_addr(),
                                r_handle,
                                w_handle,
                                remote_sender.clone(),
                            )
                            .await;

                        match remote_sender.send(packet.clone()).await {
                            Ok(_) => {}
                            Err(err) => {
                                error!("failed to send packet to remote: {}", err);
                            }
                        };
                    }
                    Some(handle) => match handle.send(packet).await {
                        Ok(_) => {
                            debug!("reusing {} sent to remote", sess);
                        }
                        Err(err) => {
                            error!("failed to send packet to remote: {}", err);
                        }
                    },
                };
            }

            trace!("UDP session local -> remote finished for {}", ss);
        });

        let ss = s.clone();
        let t2 = tokio::spawn(async move {
            while let Some(packet) = remote_receiver_r.recv().await {
                match local_w.send(packet.clone()).await {
                    Ok(_) => {}
                    Err(err) => {
                        error!(
                            "failed to send packet to local: {}, packet: {}",
                            err, packet
                        );
                    }
                }
            }
            trace!("UDP session remote -> local finished for {}", ss);
        });

        let (close_sender, close_receiver) = tokio::sync::oneshot::channel::<u8>();

        tokio::spawn(async move {
            let _ = close_receiver.await;
            trace!("UDP close signal for {} received", s);
            t1.abort();
            t2.abort();
        });

        return close_sender;
    }
}

type OutboundPacketSender = tokio::sync::mpsc::Sender<UdpPacket>; // outbound packet sender

struct TimeoutUdpSessionManager {
    map: Arc<RwLock<OutboundHandleMap>>,

    cleaner: Option<JoinHandle<()>>,
}

impl Drop for TimeoutUdpSessionManager {
    fn drop(&mut self) {
        trace!("dropping timeout udp session manager");
        self.cleaner.take().map(|x| x.abort());
    }
}

impl TimeoutUdpSessionManager {
    fn new() -> Self {
        let map = Arc::new(RwLock::new(OutboundHandleMap::new()));
        let timeout = Duration::from_secs(10);

        let map_cloned = map.clone();

        let cleaner = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;

                trace!("timeout udp session cleaner scanning");
                let mut g = map_cloned.write().await;
                let mut alived = 0;
                let mut expired = 0;
                g.0.retain(|k, x| {
                    let (h1, h2, _, last) = x;
                    let now = Instant::now();
                    let alive = now.duration_since(*last) < timeout;
                    if !alive {
                        expired += 1;
                        trace!("udp session expired: {:?}", k);
                        h1.abort();
                        h2.abort();
                    } else {
                        alived += 1;
                    }
                    alive
                });
                trace!(
                    "timeout udp session cleaner finished, alived: {}, expired: {}",
                    alived,
                    expired
                );
            }
        });

        Self {
            map,

            cleaner: Some(cleaner),
        }
    }

    async fn insert(
        &self,
        outbound_name: &str,
        src_addr: SocketAddr,
        recv_handle: JoinHandle<()>,
        send_handle: JoinHandle<()>,
        sender: OutboundPacketSender,
    ) {
        let mut map = self.map.write().await;
        map.insert(outbound_name, src_addr, recv_handle, send_handle, sender);
    }

    async fn get_outbound_sender_mut(
        &self,
        outbound_name: &str,
        src_addr: SocketAddr,
    ) -> Option<OutboundPacketSender> {
        let mut map = self.map.write().await;
        map.get_outbound_sender_mut(outbound_name, src_addr)
    }
}

struct OutboundHandleMap(
    HashMap<
        (String, SocketAddr),
        (
            JoinHandle<()>,
            JoinHandle<()>,
            OutboundPacketSender,
            Instant,
        ),
    >,
);

impl OutboundHandleMap {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn insert(
        &mut self,
        outbound_name: &str,
        src_addr: SocketAddr,
        recv_handle: JoinHandle<()>,
        send_handle: JoinHandle<()>,
        sender: OutboundPacketSender,
    ) {
        self.0.insert(
            (outbound_name.to_string(), src_addr),
            (recv_handle, send_handle, sender, Instant::now()),
        );
    }

    fn get_outbound_sender_mut(
        &mut self,
        outbound_name: &str,
        src_addr: SocketAddr,
    ) -> Option<OutboundPacketSender> {
        self.0
            .get_mut(&(outbound_name.to_owned(), src_addr))
            .map(|(_, _, sender, last)| {
                trace!(
                    "updating last access time for outbound {:?}",
                    (outbound_name, src_addr)
                );
                *last = Instant::now();
                sender.clone()
            })
    }
}

impl Drop for OutboundHandleMap {
    fn drop(&mut self) {
        trace!(
            "dropping inner outbound handle map that has {} sessions",
            self.0.len()
        );
        for (_, (recv_handle, send_handle, _, _)) in self.0.drain() {
            recv_handle.abort();
            send_handle.abort();
        }
    }
}
