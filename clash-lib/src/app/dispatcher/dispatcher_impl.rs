use crate::{
    app::{
        dispatcher::tracked::{TrackedDatagram, TrackedStream},
        dns::ClashResolver,
        outbound::manager::ThreadSafeOutboundManager,
        router::ArcRouter,
    },
    common::io::copy_bidirectional,
    config::{
        def::RunMode,
        internal::proxy::{PROXY_DIRECT, PROXY_GLOBAL},
    },
    proxy::{
        AnyInboundDatagram, ClientStream, datagram::UdpPacket, utils::ToCanonical,
    },
    session::{Session, SocksAddr},
};
use futures::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, sync::RwLock, task::JoinHandle};
use tracing::{Instrument, debug, error, info, info_span, instrument, trace, warn};

use crate::app::dns::ThreadSafeDNSResolver;

use super::statistics_manager::Manager;

// SS2022 (AEAD-2022) MAX_PACKET_SIZE is 0xFFFF (65535 bytes). Using a relay
// buffer smaller than that forces the cipher to split every full packet into
// multiple smaller encrypted chunks, multiplying encrypt/decrypt overhead.
// Classic AEAD ciphers cap at 0x3FFF (16383 bytes) so they are unaffected.
const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
    resolver: ThreadSafeDNSResolver,
    mode: Arc<RwLock<RunMode>>,
    manager: Arc<Manager>,
    tcp_buffer_size: usize,
}

impl Debug for Dispatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher").finish()
    }
}

impl Dispatcher {
    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        router: ArcRouter,
        resolver: ThreadSafeDNSResolver,
        mode: RunMode,
        statistics_manager: Arc<Manager>,
        tcp_buffer_size: Option<usize>,
    ) -> Self {
        Self {
            outbound_manager,
            router,
            resolver,
            mode: Arc::new(RwLock::new(mode)),
            manager: statistics_manager,
            tcp_buffer_size: tcp_buffer_size.unwrap_or(DEFAULT_BUFFER_SIZE),
        }
    }

    pub async fn set_mode(&self, mode: RunMode) {
        info!("run mode switched to {}", mode);

        *self.mode.write().await = mode;
    }

    pub async fn get_mode(&self) -> RunMode {
        *self.mode.read().await
    }

    #[instrument(skip(self, sess, lhs))]
    pub async fn dispatch_stream(
        &self,
        mut sess: Session,
        mut lhs: Box<dyn ClientStream>,
    ) {
        let dest: SocksAddr =
            match reverse_lookup(&self.resolver, &sess.destination).await {
                Some(dest) => dest,
                None => {
                    warn!("failed to resolve destination {}", sess);
                    return;
                }
            };

        sess.destination = dest.clone();

        let mode = *self.mode.read().await;
        let (outbound_name, rule) = match mode {
            RunMode::Global => (PROXY_GLOBAL, None),
            RunMode::Rule => self.router.match_route(&mut sess).await,
            RunMode::Direct => (PROXY_DIRECT, None),
        };

        debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);

        let mgr = self.outbound_manager.clone();
        let handler = match mgr.get_outbound(outbound_name).await {
            Some(h) => h,
            None => {
                debug!("unknown rule: {}, fallback to direct", outbound_name);
                mgr.get_outbound(PROXY_DIRECT).await.unwrap()
            }
        };

        match handler
            .connect_stream(&sess, self.resolver.clone())
            .instrument(info_span!("connect_stream", outbound_name = outbound_name,))
            .await
        {
            Ok(rhs) => {
                debug!("remote connection established {}", sess);
                let rhs = TrackedStream::new(
                    rhs,
                    self.manager.clone(),
                    sess.clone(),
                    rule,
                )
                .await;
                match copy_bidirectional(
                    lhs,
                    rhs,
                    self.tcp_buffer_size,
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                )
                .instrument(info_span!(
                    "copy_bidirectional",
                    outbound_name = outbound_name,
                ))
                .await
                {
                    Ok((up, down)) => {
                        debug!(
                            "connection {} closed with {} bytes up, {} bytes down",
                            sess, up, down
                        );
                    }
                    Err(err) => match err {
                        crate::common::io::CopyBidirectionalError::LeftClosed(
                            err,
                        ) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!(
                                    "connection {} closed with error {} by local",
                                    sess, err
                                );
                            }
                            _ => {
                                warn!(
                                    "connection {} closed with error {} by local",
                                    sess, err
                                );
                            }
                        },
                        crate::common::io::CopyBidirectionalError::RightClosed(
                            err,
                        ) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!(
                                    "connection {} closed with error {} by remote",
                                    sess, err
                                );
                            }
                            _ => {
                                warn!(
                                    "connection {} closed with error {} by remote",
                                    sess, err
                                );
                            }
                        },
                        crate::common::io::CopyBidirectionalError::Other(err) => {
                            match err.kind() {
                                std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::BrokenPipe => {
                                    debug!(
                                        "connection {} closed with error {}",
                                        sess, err
                                    );
                                }
                                _ => {
                                    warn!(
                                        "connection {} closed with error {}",
                                        sess, err
                                    );
                                }
                            }
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
    #[must_use]
    pub async fn dispatch_datagram(
        &self,
        sess: Session,
        udp_inbound: AnyInboundDatagram,
    ) -> tokio::sync::oneshot::Sender<u8> {
        let outbound_handle_guard = TimeoutUdpSessionManager::new();

        let router = self.router.clone();
        let outbound_manager = self.outbound_manager.clone();
        let resolver = self.resolver.clone();
        let mode = self.mode.clone();
        let manager = self.manager.clone();

        #[rustfmt::skip]
        /*
         *  implement details
         *
         *  data structure:
         *    local_r, local_w: stream/sink pair
         *    remote_r, remote_w: stream/sink pair
         *    remote_receiver_r, remote_receiver_w: channel pair
         *    remote_sender, remote_forwarder: channel pair
         *
         *  data flow:
         *    => local_r => init packet => connect_datagram => remote_sender     => remote_forwarder         => remote_w
         *    => local_w                                    <= remote_receiver_r <= NAT + remote_receiver_w  <= remote_r
         *
         *  notice:
         *    the NAT is binded to the session in the dispatch_datagram function arg and the closure
         *    so we need not to add a global NAT table and do the translation
         */
        let (mut local_w, mut local_r) = udp_inbound.split();
        let (remote_receiver_w, mut remote_receiver_r) =
            tokio::sync::mpsc::channel(256);

        let s = sess.clone();
        let ss = sess.clone();
        let t1 = tokio::spawn(async move {
            while let Some(mut packet) = local_r.next().await {
                let mut sess = sess.clone();

                // Canonicalize IPv4-mapped IPv6 destination addresses to plain
                // IPv4 (e.g. SS2022 inbound on a dual-stack socket may produce
                // ::ffff:x.x.x.x for an IPv4 target), then preserve the IP for
                // family_hint_for_session before reverse_lookup may replace it
                // with a domain name.  Without canonicalization, new_udp_socket
                // picks AF_INET6 while bind_addr is 0.0.0.0, causing EINVAL.
                if let crate::session::SocksAddr::Ip(addr) = &mut packet.dst_addr {
                    *addr = addr.to_canonical();
                    sess.resolved_ip = Some(addr.ip());
                }

                let dest = match reverse_lookup(&resolver, &packet.dst_addr).await {
                    Some(dest) => dest,
                    None => {
                        warn!("failed to resolve destination {}", sess);
                        continue;
                    }
                };

                // for TUN or Tproxy, we need the original destination address
                let orig_dest = packet.dst_addr.clone();
                sess.source = packet.src_addr.clone().must_into_socket_addr();
                sess.destination = dest.clone();
                sess.inbound_user = packet.inbound_user.clone();

                // mutate packet for fake ip
                // resolve is done in OutboundDatagramImpl so it's fine to have
                // (Domain, port) here. ideally the OutboundDatagramImpl should only
                // do Ip though?
                packet.dst_addr = dest.clone();

                let mode = *mode.read().await;

                let (outbound_name, rule) = match mode {
                    RunMode::Global => (PROXY_GLOBAL, None),
                    RunMode::Rule => router.match_route(&mut sess).await,
                    RunMode::Direct => (PROXY_DIRECT, None),
                };

                let outbound_name = outbound_name.to_string();

                debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);

                let remote_receiver_w = remote_receiver_w.clone();

                let mgr = outbound_manager.clone();
                let handler = match mgr.get_outbound(&outbound_name).await {
                    Some(h) => h,
                    None => {
                        debug!(
                            "unknown rule: {}, fallback to direct",
                            outbound_name
                        );
                        mgr.get_outbound(PROXY_DIRECT).await.unwrap()
                    }
                };

                let outbound_name =
                    if let Some(group) = handler.try_as_group_handler() {
                        group
                            .get_active_proxy()
                            .await
                            .map(|x| x.name().to_owned())
                            .unwrap_or(outbound_name)
                    } else {
                        outbound_name
                    };

                match outbound_handle_guard
                    .get_outbound_sender_mut(
                        &outbound_name,
                        packet.src_addr.clone().must_into_socket_addr(), /* this is only
                                                                          * expected to be
                                                                          * socket addr as it's
                                                                          * from local
                                                                          * udp */
                    )
                    .await
                {
                    None => {
                        debug!("building {} outbound datagram connecting", sess);
                        let outbound_datagram = match handler
                            .connect_datagram(&sess, resolver.clone())
                            .await
                        {
                            Ok(v) => v,
                            Err(err) => {
                                error!("failed to connect outbound: {}", err);
                                continue;
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
                            tokio::sync::mpsc::channel::<UdpPacket>(256);

                        // Channel that t1 uses to push (dest → orig_dest) mappings
                        // into r_handle's local lookup table
                        // as new destinations are seen on
                        // the same client socket.
                        let (dest_tx, mut dest_rx) =
                            tokio::sync::mpsc::unbounded_channel::<(
                                SocksAddr,
                                SocksAddr,
                            )>();
                        // Seed with the current packet's mapping before spawning.
                        dest_tx.send((dest.clone(), orig_dest.clone())).ok();

                        // remote -> local
                        let r_handle = tokio::spawn(async move {
                            // Maps the logical destination (domain or real IP) that
                            // was sent to, back to the
                            // original inbound destination (e.g.
                            // fake-IP). Populated/updated via dest_rx.
                            let mut dest_to_orig: HashMap<SocksAddr, SocksAddr> =
                                HashMap::new();
                            loop {
                                tokio::select! {
                                    biased; // drain updates before processing packets

                                    update = dest_rx.recv() => {
                                        match update {
                                            Some((d, o)) => { dest_to_orig.insert(d, o); }
                                            None => break,
                                        }
                                    }

                                    packet = remote_r.next() => {
                                        match packet {
                                            None => break,
                                            Some(mut packet) => {
                                                // src_addr is the domain from ip_to_domain
                                                // in OutboundDatagramImpl, or a real IP.
                                                // Map it back to the original inbound dest.
                                                let nat_src = dest_to_orig
                                                    .get(&packet.src_addr)
                                                    .cloned()
                                                    .unwrap_or_else(|| packet.src_addr.clone());
                                                packet.src_addr = nat_src;
                                                packet.dst_addr = sess.source.into();

                                                debug!(
                                                    "UDP NAT for packet: {:?}, session: {}",
                                                    packet, sess
                                                );
                                                match remote_receiver_w.send(packet).await {
                                                    Ok(_) => {}
                                                    Err(err) => {
                                                        warn!(
                                                            "failed to send packet to \
                                                             local: {}",
                                                            err
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        });
                        // local -> remote
                        let w_handle = tokio::spawn(async move {
                            while let Some(packet) = remote_forwarder.recv().await {
                                match remote_w.send(packet).await {
                                    Ok(_) => {}
                                    Err(err) => {
                                        warn!(
                                            "failed to send packet to remote: \
                                             {err:?}"
                                        );
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
                                dest_tx,
                            )
                            .await;

                        match remote_sender.send(packet).await {
                            Ok(_) => {}
                            Err(err) => {
                                error!("failed to send packet to remote: {}", err);
                            }
                        };
                    }
                    Some((handle, dest_updater)) => {
                        // Inform r_handle about the (potentially new) destination
                        // mapping for this packet so responses are stamped
                        // correctly.
                        dest_updater.send((dest.clone(), orig_dest.clone())).ok();
                        match handle.send(packet).await {
                            // TODO: need to reset when GLOBAL select is changed
                            Ok(_) => {
                                debug!("reusing {} sent to remote", sess);
                            }
                            Err(err) => {
                                error!("failed to send packet to remote: {}", err);
                            }
                        }
                    }
                };
            }

            trace!("UDP session local -> remote finished for {}", ss);
        });

        let ss = s.clone();
        let t2 = tokio::spawn(async move {
            while let Some(packet) = remote_receiver_r.recv().await {
                match local_w.send(packet).await {
                    Ok(_) => {}
                    Err(err) => {
                        error!("failed to send packet to local: {}", err);
                    }
                }
            }
            trace!("UDP session remote -> local finished for {}", ss);
        });

        let (close_sender, close_receiver) = tokio::sync::oneshot::channel::<u8>();

        tokio::spawn(async move {
            if close_receiver.await.is_ok() {
                trace!("UDP close signal for {} received", s);
                t1.abort();
                t2.abort();
            } else {
                error!("UDP close signal dropped!");
            }
        });

        close_sender
    }
}

// helper function to resolve the destination address
// if the destination is an IP address, check if it's a fake IP
// or look for cached IP
// if the destination is a domain name, don't resolve
async fn reverse_lookup(
    resolver: &Arc<dyn ClashResolver>,
    dst: &SocksAddr,
) -> Option<SocksAddr> {
    let dst = match dst {
        crate::session::SocksAddr::Ip(socket_addr) => {
            if resolver.fake_ip_enabled() {
                let ip = socket_addr.ip();
                if resolver.is_fake_ip(ip).await {
                    trace!("looking up fake ip: {}", socket_addr.ip());
                    let host = resolver.reverse_lookup(ip).await;
                    match host {
                        Some(host) => (host, socket_addr.port())
                            .try_into()
                            .expect("must be valid domain"),
                        None => {
                            error!("failed to reverse lookup fake ip: {}", ip);
                            return None;
                        }
                    }
                } else {
                    (*socket_addr).into()
                }
            } else {
                trace!("looking up resolve cache ip: {}", socket_addr.ip());
                match resolver.cached_for(socket_addr.ip()).await {
                    Some(resolved) => (resolved, socket_addr.port())
                        .try_into()
                        .expect("must be valid domain"),
                    _ => (*socket_addr).into(),
                }
            }
        }
        crate::session::SocksAddr::Domain(host, port) => (host.to_owned(), *port)
            .try_into()
            .expect("must be valid domain"),
    };
    Some(dst)
}

type OutboundPacketSender = tokio::sync::mpsc::Sender<UdpPacket>; // outbound packet sender

struct TimeoutUdpSessionManager {
    map: Arc<RwLock<OutboundHandleMap>>,

    cleaner: Option<JoinHandle<()>>,
}

impl Drop for TimeoutUdpSessionManager {
    fn drop(&mut self) {
        trace!("dropping timeout udp session manager");
        if let Some(x) = self.cleaner.take() {
            x.abort()
        }
    }
}

impl TimeoutUdpSessionManager {
    fn new() -> Self {
        let map = Arc::new(RwLock::new(OutboundHandleMap::new()));
        let timeout = Duration::from_secs(10);

        let map_cloned = map.clone();

        let cleaner = tokio::spawn(async move {
            trace!("timeout udp session cleaner scanning");
            let mut interval = tokio::time::interval(timeout);

            loop {
                interval.tick().await;
                trace!("timeout udp session cleaner ticking");

                let mut g = map_cloned.write().await;
                let mut alived = 0;
                let mut expired = 0;
                g.0.retain(|k, val| {
                    let now = Instant::now();
                    let alive = now.duration_since(val.last_active) < timeout;
                    if !alive {
                        expired += 1;
                        trace!("udp session expired: {:?}", k);
                        val.recv_handle.abort();
                        val.send_handle.abort();
                    } else {
                        alived += 1;
                    }
                    alive
                });
                trace!(
                    "timeout udp session cleaner finished, alived: {}, expired: {}",
                    alived, expired
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
        dest_updater: DestUpdateSender,
    ) {
        let mut map = self.map.write().await;
        map.insert(
            outbound_name,
            src_addr,
            recv_handle,
            send_handle,
            sender,
            dest_updater,
        );
    }

    async fn get_outbound_sender_mut(
        &self,
        outbound_name: &str,
        src_addr: SocketAddr,
    ) -> Option<(OutboundPacketSender, DestUpdateSender)> {
        let mut map = self.map.write().await;
        map.get_outbound_sender_mut(outbound_name, src_addr)
    }
}

/// Key identifying a unique UDP NAT session.
/// Scoped to (outbound, client source) — one socket per client, full cone NAT.
#[derive(Debug, PartialEq, Eq, Hash)]
struct OutboundHandleKey {
    outbound_name: String,
    src_addr: SocketAddr,
}

type DestUpdateSender = tokio::sync::mpsc::UnboundedSender<(SocksAddr, SocksAddr)>;

struct OutboundHandleVal {
    recv_handle: JoinHandle<()>,
    send_handle: JoinHandle<()>,
    sender: OutboundPacketSender,
    /// Channel to inform `r_handle` about new (dest → orig_dest) mappings as
    /// the same client socket sends packets to different destinations.
    dest_updater: DestUpdateSender,
    last_active: Instant,
}

struct OutboundHandleMap(HashMap<OutboundHandleKey, OutboundHandleVal>);

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
        dest_updater: DestUpdateSender,
    ) {
        self.0.insert(
            OutboundHandleKey {
                outbound_name: outbound_name.to_string(),
                src_addr,
            },
            OutboundHandleVal {
                recv_handle,
                send_handle,
                sender,
                dest_updater,
                last_active: Instant::now(),
            },
        );
    }

    fn get_outbound_sender_mut(
        &mut self,
        outbound_name: &str,
        src_addr: SocketAddr,
    ) -> Option<(OutboundPacketSender, DestUpdateSender)> {
        let key = OutboundHandleKey {
            outbound_name: outbound_name.to_owned(),
            src_addr,
        };
        self.0.get_mut(&key).map(|val| {
            trace!(
                "updating last access time for outbound {:?}",
                (outbound_name, src_addr)
            );
            val.last_active = Instant::now();
            (val.sender.clone(), val.dest_updater.clone())
        })
    }
}

impl Drop for OutboundHandleMap {
    fn drop(&mut self) {
        trace!(
            "dropping inner outbound handle map that has {} sessions",
            self.0.len()
        );
        for (_, val) in self.0.drain() {
            val.recv_handle.abort();
            val.send_handle.abort();
        }
    }
}
