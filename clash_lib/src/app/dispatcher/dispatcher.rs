use crate::app::dispatcher::tracked::TrackedDatagram;
use crate::app::dispatcher::tracked::TrackedStream;
use crate::app::outbound::manager::ThreadSafeOutboundManager;
use crate::app::router::ThreadSafeRouter;
use crate::config::def::RunMode;
use crate::config::internal::proxy::PROXY_DIRECT;
use crate::config::internal::proxy::PROXY_GLOBAL;
use crate::proxy::datagram::UdpPacket;
use crate::proxy::AnyInboundDatagram;
use crate::session::Session;
use futures::SinkExt;
use futures::StreamExt;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use tracing::{event, instrument};

use crate::app::dns::ThreadSafeDNSResolver;

use super::statistics_manager::Manager;

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ThreadSafeRouter,
    resolver: ThreadSafeDNSResolver,
    mode: Arc<Mutex<RunMode>>,

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
            mode: Arc::new(Mutex::new(mode)),
            manager: statistics_manager,
        }
    }

    pub async fn set_mode(&self, mode: RunMode) {
        info!("run mode switched to {}", mode);
        let mut m = self.mode.lock().await;
        *m = mode;
    }

    pub async fn get_mode(&self) -> RunMode {
        let mode = self.mode.lock().await;
        mode.clone()
    }

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

        let mode = self.mode.lock().await;
        info!("dispatching {} with mode {}", sess, mode);
        let (outbound_name, rule) = match *mode {
            RunMode::Global => (PROXY_GLOBAL, None),
            RunMode::Rule => self.router.match_route(&sess).await,
            RunMode::Direct => (PROXY_DIRECT, None),
        };

        let handler = self
            .outbound_manager
            .read()
            .await
            .get_outbound(outbound_name)
            .expect(format!("unknown rule: {}", outbound_name).as_str()); // should never happen

        match handler.connect_stream(&sess, self.resolver.clone()).await {
            Ok(rhs) => {
                info!("remote connection established {}", sess);
                let mut rhs = Box::new(
                    TrackedStream::new(rhs, self.manager.clone(), sess.clone(), rule).await,
                );
                match copy_bidirectional(&mut lhs, &mut rhs).await {
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
        let outbound_handle_guard = Arc::new(Mutex::new(OutboundHandleMap::new()));

        let router = self.router.clone();
        let outbound_manager = self.outbound_manager.clone();
        let resolver = self.resolver.clone();
        let mode = self.mode.clone();
        let manager = self.manager.clone();

        let (mut local_w, mut local_r) = udp_inbound.split();
        let (remote_receiver_w, mut remote_receiver_r) = tokio::sync::mpsc::channel(32);

        let s = sess.clone();
        let t1 = tokio::spawn(async move {
            while let Some(packet) = local_r.next().await {
                let mut sess = sess.clone();
                sess.source = packet.src_addr.clone().must_into_socket_addr();
                sess.destination = packet.dst_addr.clone();

                let sess = if resolver.fake_ip_enabled() {
                    match sess.destination {
                        crate::session::SocksAddr::Ip(addr) => {
                            let ip = addr.ip();
                            if resolver.is_fake_ip(ip).await {
                                let host = resolver.reverse_lookup(ip).await;
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

                let mode = mode.lock().await;
                info!("dispatching {} with mode {}", sess, mode);
                let (outbound_name, rule) = match *mode {
                    RunMode::Global => (PROXY_GLOBAL, None),
                    RunMode::Rule => router.match_route(&sess).await,
                    RunMode::Direct => (PROXY_DIRECT, None),
                };

                let outbound_name = outbound_name.to_string();

                let remote_receiver_w = remote_receiver_w.clone();

                let handler = outbound_manager
                    .read()
                    .await
                    .get_outbound(&outbound_name)
                    .expect(format!("unknown rule: {}", outbound_name).as_str());

                let mut outbound_handle_guard = outbound_handle_guard.lock().await;

                match outbound_handle_guard.get_outbound_sender_mut(&outbound_name) {
                    None => {
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

                        outbound_handle_guard.insert(
                            &outbound_name,
                            r_handle,
                            w_handle,
                            remote_sender.clone(),
                        );

                        drop(outbound_handle_guard);

                        match remote_sender.send(packet.clone()).await {
                            Ok(_) => {
                                event!(tracing::Level::DEBUG, "local -> remote: packet sent");
                            }
                            Err(err) => {
                                error!("failed to send packet to remote: {}", err);
                            }
                        };
                    }
                    Some(handle) => match handle.send(packet).await {
                        Ok(_) => {}
                        Err(err) => {
                            error!("failed to send packet to remote: {}", err);
                        }
                    },
                };
            }
        });

        let t2 = tokio::spawn(async move {
            while let Some(packet) = remote_receiver_r.recv().await {
                event!(
                    tracing::Level::DEBUG,
                    "remote -> local: packet received: {:?}",
                    packet
                );
                match local_w.send(packet.clone()).await {
                    Ok(_) => {
                        event!(tracing::Level::DEBUG, "outer remote -> local: packet sent");
                    }
                    Err(err) => {
                        error!(
                            "failed to send packet to local: {}, packet: {}",
                            err, packet
                        );
                    }
                }
            }
        });

        let (close_sender, close_receiver) = tokio::sync::oneshot::channel::<u8>();

        tokio::spawn(async move {
            let _ = close_receiver.await;
            debug!("UDP close signal for {} received", s);
            t1.abort();
            t2.abort();
        });

        return close_sender;
    }
}

type OutBoundPacketSender = tokio::sync::mpsc::Sender<UdpPacket>; // outbound packet sender
struct OutboundHandleMap(HashMap<String, (JoinHandle<()>, JoinHandle<()>, OutBoundPacketSender)>);

impl OutboundHandleMap {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn insert(
        &mut self,
        outbound_name: &str,
        recv_handle: JoinHandle<()>,
        send_handle: JoinHandle<()>,
        sender: OutBoundPacketSender,
    ) {
        self.0.insert(
            outbound_name.to_string(),
            (recv_handle, send_handle, sender),
        );
    }

    fn get_outbound_sender_mut(
        &mut self,
        outbound_name: &str,
    ) -> Option<&mut OutBoundPacketSender> {
        self.0.get_mut(outbound_name).map(|(_, _, sender)| sender)
    }
}

impl Drop for OutboundHandleMap {
    fn drop(&mut self) {
        debug!("dropping outbound handle map");
        for (_, (recv_handle, send_handle, _)) in self.0.drain() {
            recv_handle.abort();
            send_handle.abort();
        }
    }
}
