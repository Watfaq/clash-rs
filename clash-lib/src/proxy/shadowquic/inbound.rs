use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, ready};
use shadowquic::{
    SDecode, SEncode,
    config::{
        AuthUser, JlsUpstream, ShadowQuicServerCfg, default_blackhole_detection,
        default_gso, default_initial_mtu, default_min_mtu, default_mtu_discovery,
        default_zero_rtt,
    },
    error::SError,
    msgs::{
        socks5::SocksAddr as SQAddr,
        squic::{SQPacketDatagramHeader, SQReq, SQUdpControlHeader},
    },
    quic::{QuicConnection, QuicServer},
    shadowquic::EndServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Mutex, mpsc},
};
use tokio_util::sync::PollSender;
use tracing::{debug, info, warn};

use crate::{
    Dispatcher,
    common::errors::new_io_error,
    config::internal::listener::{ShadowQuicInboundUser, ShadowQuicJlsUpstream},
    proxy::{datagram::UdpPacket, inbound::InboundHandlerTrait},
    session::{Network, Session, SocksAddr, Type},
};

use super::{to_clash_socks_addr, to_sq_socks_addr};

const MAX_UDP_ROUTES_PER_CONN: usize = 1024;
const MAX_UDP_PENDING_IDS_PER_CONN: usize = 256;
const MAX_UDP_PENDING_PACKETS_PER_ID: usize = 16;
const MAX_UDP_RESPONSE_DESTS_PER_ASSOC: usize = 1024;

pub struct InboundOptions {
    pub addr: SocketAddr,
    pub allow_lan: bool,
    pub dispatcher: Arc<Dispatcher>,
    pub fw_mark: Option<u32>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub users: Vec<ShadowQuicInboundUser>,
    pub server_name: Option<String>,
    pub jls_upstream: ShadowQuicJlsUpstream,
    pub alpn: Option<Vec<String>>,
    pub zero_rtt: Option<bool>,
    pub congestion_control: Option<shadowquic::config::CongestionControl>,
    pub initial_mtu: Option<u16>,
    pub min_mtu: Option<u16>,
    pub gso: Option<bool>,
    pub mtu_discovery: Option<bool>,
    pub blackhole_detection: Option<bool>,
}

pub struct ShadowQuicInbound {
    opts: InboundOptions,
}

impl ShadowQuicInbound {
    pub fn new(opts: InboundOptions) -> io::Result<Self> {
        let has_single_user = opts.username.is_some() || opts.password.is_some();
        if has_single_user && (opts.username.is_none() || opts.password.is_none()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shadowquic inbound requires both username and password",
            ));
        }
        if !has_single_user && opts.users.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shadowquic inbound requires username/password or users",
            ));
        }
        Ok(Self { opts })
    }

    fn build_server_config(&self) -> ShadowQuicServerCfg {
        let mut users = self
            .opts
            .users
            .iter()
            .map(|u| AuthUser {
                username: u.username.clone(),
                password: u.password.clone(),
            })
            .collect::<Vec<_>>();

        if let (Some(username), Some(password)) =
            (&self.opts.username, &self.opts.password)
        {
            users.push(AuthUser {
                username: username.clone(),
                password: password.clone(),
            });
        }

        ShadowQuicServerCfg {
            bind_addr: self.opts.addr,
            users,
            server_name: self.opts.server_name.clone(),
            jls_upstream: JlsUpstream {
                addr: self.opts.jls_upstream.addr.clone(),
                rate_limit: self.opts.jls_upstream.rate_limit.unwrap_or(u64::MAX),
            },
            alpn: self
                .opts
                .alpn
                .clone()
                .unwrap_or_else(|| vec!["h3".to_owned()]),
            zero_rtt: self.opts.zero_rtt.unwrap_or_else(default_zero_rtt),
            congestion_control: self
                .opts
                .congestion_control
                .clone()
                .unwrap_or_default(),
            initial_mtu: self.opts.initial_mtu.unwrap_or_else(default_initial_mtu),
            min_mtu: self.opts.min_mtu.unwrap_or_else(default_min_mtu),
            gso: self.opts.gso.unwrap_or_else(default_gso),
            mtu_discovery: self
                .opts
                .mtu_discovery
                .unwrap_or_else(default_mtu_discovery),
            blackhole_detection: self
                .opts
                .blackhole_detection
                .unwrap_or_else(default_blackhole_detection),
        }
    }

    fn source_allowed(&self, source: SocketAddr) -> bool {
        self.opts.allow_lan
            || self.opts.addr.ip().is_unspecified()
            || source.ip() == self.opts.addr.ip()
    }
}

impl Drop for ShadowQuicInbound {
    fn drop(&mut self) {
        warn!("ShadowQUIC inbound listener on {} stopped", self.opts.addr);
    }
}

#[async_trait]
impl InboundHandlerTrait for ShadowQuicInbound {
    fn handle_tcp(&self) -> bool {
        false
    }

    fn handle_udp(&self) -> bool {
        true
    }

    async fn listen_tcp(&self) -> io::Result<()> {
        Ok(())
    }

    async fn listen_udp(&self) -> io::Result<()> {
        let cfg = self.build_server_config();
        let endpoint = EndServer::new(&cfg).await.map_err(new_io_error)?;

        loop {
            let conn = match endpoint.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("shadowquic inbound accept error: {e}");
                    continue;
                }
            };
            let source = canonical_addr(conn.remote_address());
            if !self.source_allowed(source) {
                warn!(
                    "shadowquic inbound {}: connection from {} rejected (not allowed)",
                    self.opts.addr, source
                );
                QuicConnection::close(&conn, 0, b"source not allowed");
                continue;
            }

            let dispatcher = self.opts.dispatcher.clone();
            let fw_mark = self.opts.fw_mark;
            let inbound_user = None;
            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    conn,
                    source,
                    dispatcher,
                    fw_mark,
                    inbound_user,
                )
                .await
                {
                    warn!("shadowquic inbound connection {source} ended: {e}");
                }
            });
        }
    }
}

fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|v4| SocketAddr::from((v4, v6.port())))
            .unwrap_or(addr),
        _ => addr,
    }
}

async fn handle_connection<C>(
    conn: C,
    source: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
    inbound_user: Option<String>,
) -> Result<(), SError>
where
    C: QuicConnection + Clone + Send + Sync + 'static,
{
    info!(peer = %source, "shadowquic inbound connection accepted");
    let state = Arc::new(ConnState::new(conn.clone()));
    tokio::spawn({
        let conn = conn.clone();
        let state = state.clone();
        async move {
            if let Err(e) = run_udp_demux(conn, state).await {
                debug!("shadowquic inbound UDP demux ended: {e}");
            }
        }
    });

    while conn.close_reason().is_none() {
        let (send, mut recv, id) = conn.accept_bi().await?;
        debug!(stream_id = id, "shadowquic inbound bistream accepted");

        let req = SQReq::decode(&mut recv).await?;
        let dispatcher = dispatcher.clone();
        let state = state.clone();
        let conn = conn.clone();
        let inbound_user = inbound_user.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_request(
                conn,
                state,
                source,
                fw_mark,
                inbound_user,
                dispatcher,
                send,
                recv,
                req,
            )
            .await
            {
                warn!("shadowquic inbound request failed: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_request<C>(
    conn: C,
    state: Arc<ConnState<C>>,
    source: SocketAddr,
    fw_mark: Option<u32>,
    inbound_user: Option<String>,
    dispatcher: Arc<Dispatcher>,
    send: C::SendStream,
    recv: C::RecvStream,
    req: SQReq,
) -> Result<(), SError>
where
    C: QuicConnection + Clone + Send + Sync + 'static,
{
    match req {
        SQReq::SQConnect(dst) => {
            let destination = to_clash_socks_addr(dst).map_err(SError::Io)?;
            let sess = Session {
                network: Network::Tcp,
                typ: Type::ShadowQuic,
                source,
                destination,
                so_mark: fw_mark,
                inbound_user,
                ..Default::default()
            };
            dispatcher
                .dispatch_stream(sess, Box::new(Unsplit { send, recv }))
                .await;
        }
        SQReq::SQAssociatOverDatagram(bind_addr) => {
            handle_udp_associate(
                conn,
                state,
                source,
                fw_mark,
                inbound_user,
                dispatcher,
                send,
                recv,
                bind_addr,
                false,
            )
            .await?;
        }
        SQReq::SQAssociatOverStream(bind_addr) => {
            handle_udp_associate(
                conn,
                state,
                source,
                fw_mark,
                inbound_user,
                dispatcher,
                send,
                recv,
                bind_addr,
                true,
            )
            .await?;
        }
        SQReq::SQBind(_) => {
            warn!("shadowquic inbound SQBind is not supported");
        }
        SQReq::SQAuthenticate(_) => {
            warn!("shadowquic inbound received unexpected SQAuthenticate");
        }
        SQReq::SQExtension(_) => {
            warn!("shadowquic inbound SQExtension is not supported in clash-rs");
        }
        #[allow(unreachable_patterns)]
        _ => {
            warn!("shadowquic inbound received unsupported request");
        }
    }
    Ok(())
}

async fn handle_udp_associate<C>(
    conn: C,
    state: Arc<ConnState<C>>,
    source: SocketAddr,
    fw_mark: Option<u32>,
    inbound_user: Option<String>,
    dispatcher: Arc<Dispatcher>,
    send: C::SendStream,
    recv: C::RecvStream,
    _bind_addr: SQAddr,
    over_stream: bool,
) -> Result<(), SError>
where
    C: QuicConnection + Clone + Send + Sync + 'static,
{
    let (request_tx, request_rx) = mpsc::channel::<(Bytes, SQAddr)>(256);
    let (response_tx, response_rx) = mpsc::channel::<(Bytes, SQAddr)>(256);

    let read_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = read_udp_control(recv, read_state, request_tx).await {
            debug!("shadowquic inbound UDP control stream ended: {e}");
        }
    });
    tokio::spawn(async move {
        if let Err(e) =
            write_udp_packets(conn, state, send, response_rx, over_stream).await
        {
            debug!("shadowquic inbound UDP writer ended: {e}");
        }
    });

    let datagram = ShadowQuicInboundDatagram {
        request_rx,
        response_tx: PollSender::new(response_tx),
        source,
        inbound_user,
    };

    let sess = Session {
        network: Network::Udp,
        typ: Type::ShadowQuic,
        source,
        so_mark: fw_mark,
        ..Default::default()
    };

    _ = dispatcher.dispatch_datagram(sess, Box::new(datagram)).await;
    Ok(())
}

async fn read_udp_control<C>(
    mut recv: C::RecvStream,
    state: Arc<ConnState<C>>,
    request_tx: mpsc::Sender<(Bytes, SQAddr)>,
) -> Result<(), SError>
where
    C: QuicConnection + Clone + Send + Sync + 'static,
{
    let mut registered = Vec::new();
    let result = async {
        loop {
            let SQUdpControlHeader { id, dst } =
                SQUdpControlHeader::decode(&mut recv).await?;
            state
                .register_inbound_id(id, dst, request_tx.clone())
                .await?;
            registered.push(id);
        }
    }
    .await;
    state.unregister_inbound_ids(&registered).await;
    result
}

async fn write_udp_packets<C>(
    conn: C,
    state: Arc<ConnState<C>>,
    mut send: C::SendStream,
    mut response_rx: mpsc::Receiver<(Bytes, SQAddr)>,
    over_stream: bool,
) -> Result<(), SError>
where
    C: QuicConnection + Clone + Send + Sync + 'static,
{
    let mut ids = HashMap::<SQAddr, u16>::new();
    let mut streams = HashMap::<SQAddr, C::SendStream>::new();

    while let Some((bytes, dst)) = response_rx.recv().await {
        let (id, is_new) = if let Some(id) = ids.get(&dst).copied() {
            (id, false)
        } else {
            if ids.len() >= MAX_UDP_RESPONSE_DESTS_PER_ASSOC {
                warn!(
                    "shadowquic inbound UDP response destination limit reached; dropping packet to {dst}"
                );
                continue;
            }
            let id = state.next_outbound_id();
            ids.insert(dst.clone(), id);
            (id, true)
        };

        if is_new {
            SQUdpControlHeader {
                dst: dst.clone(),
                id,
            }
            .encode(&mut send)
            .await?;
        }

        if over_stream {
            if !streams.contains_key(&dst) {
                let (mut uni, _) = conn.open_uni().await?;
                SQPacketDatagramHeader { id }.encode(&mut uni).await?;
                streams.insert(dst.clone(), uni);
            }
            let Some(stream) = streams.get_mut(&dst) else {
                warn!(
                    "shadowquic inbound UDP stream missing after insertion; dropping packet to {dst}"
                );
                continue;
            };
            if bytes.len() > u16::MAX as usize {
                warn!(
                    "shadowquic inbound UDP packet too large for stream framing; dropping packet to {dst}"
                );
                continue;
            }
            (bytes.len() as u16).encode(stream).await?;
            stream.write_all(&bytes).await?;
        } else {
            let mut buf = BytesMut::with_capacity(bytes.len() + 2);
            let mut head = Vec::with_capacity(2);
            SQPacketDatagramHeader { id }.encode(&mut head).await?;
            buf.put(Bytes::from(head));
            buf.put(bytes);
            conn.send_datagram(buf.freeze()).await?;
        }
    }
    Ok(())
}

async fn run_udp_demux<C>(conn: C, state: Arc<ConnState<C>>) -> Result<(), SError>
where
    C: QuicConnection + Clone + Send + Sync + 'static,
{
    loop {
        tokio::select! {
            datagram = conn.read_datagram() => {
                let datagram = datagram?;
                let mut cur = std::io::Cursor::new(BytesMut::from(datagram));
                let SQPacketDatagramHeader { id } =
                    match SQPacketDatagramHeader::decode(&mut cur).await {
                        Ok(header) => header,
                        Err(e) => {
                            warn!("shadowquic inbound received malformed UDP datagram header: {e}");
                            continue;
                        }
                    };
                let pos = cur.position() as usize;
                if let Err(e) = state
                    .deliver_inbound_packet(id, cur.into_inner().split_off(pos).freeze())
                    .await
                {
                    warn!("shadowquic inbound dropped UDP datagram for id {id}: {e}");
                }
            }
            uni = conn.accept_uni() => {
                let (mut uni, _) = uni?;
                let state = state.clone();
                tokio::spawn(async move {
                    let result: Result<(), SError> = async {
                        let SQPacketDatagramHeader { id } =
                            SQPacketDatagramHeader::decode(&mut uni).await?;
                        loop {
                            let len = u16::decode(&mut uni).await? as usize;
                            let mut buf = BytesMut::with_capacity(len);
                            buf.resize(len, 0);
                            uni.read_exact(&mut buf).await?;
                            if let Err(e) = state.deliver_inbound_packet(id, buf.freeze()).await {
                                warn!("shadowquic inbound dropped UDP stream packet for id {id}: {e}");
                            }
                        }
                    }
                    .await;
                    if let Err(e) = result {
                        debug!("shadowquic inbound UDP unistream ended: {e}");
                    }
                });
            }
        }
    }
}

struct ConnState<C: QuicConnection> {
    next_send_id: AtomicU16,
    inbound_ids: Mutex<HashMap<u16, InboundUdpRoute>>,
    pending: Mutex<HashMap<u16, Vec<Bytes>>>,
    _marker: std::marker::PhantomData<C>,
}

struct InboundUdpRoute {
    tx: mpsc::Sender<(Bytes, SQAddr)>,
    dst: SQAddr,
}

impl<C: QuicConnection> ConnState<C> {
    fn new(_conn: C) -> Self {
        Self {
            next_send_id: AtomicU16::new(0),
            inbound_ids: Default::default(),
            pending: Default::default(),
            _marker: Default::default(),
        }
    }

    fn next_outbound_id(&self) -> u16 {
        self.next_send_id.fetch_add(1, Ordering::SeqCst)
    }

    async fn register_inbound_id(
        &self,
        id: u16,
        dst: SQAddr,
        tx: mpsc::Sender<(Bytes, SQAddr)>,
    ) -> Result<(), SError> {
        {
            let mut inbound_ids = self.inbound_ids.lock().await;
            if !inbound_ids.contains_key(&id)
                && inbound_ids.len() >= MAX_UDP_ROUTES_PER_CONN
            {
                return Err(SError::UDPSessionClosed(format!(
                    "too many UDP routes in one shadowquic connection: {}",
                    inbound_ids.len()
                )));
            }
            inbound_ids.insert(
                id,
                InboundUdpRoute {
                    tx: tx.clone(),
                    dst: dst.clone(),
                },
            );
        }

        if let Some(pending) = self.pending.lock().await.remove(&id) {
            for bytes in pending {
                if let Err(e) = tx.send((bytes, dst.clone())).await {
                    self.inbound_ids.lock().await.remove(&id);
                    return Err(SError::UDPSessionClosed(format!(
                        "UDP request channel closed while flushing pending packets: {e}"
                    )));
                }
            }
        }
        Ok(())
    }

    async fn unregister_inbound_ids(&self, ids: &[u16]) {
        if ids.is_empty() {
            return;
        }

        let mut inbound_ids = self.inbound_ids.lock().await;
        for id in ids {
            inbound_ids.remove(id);
        }
        drop(inbound_ids);

        let mut pending = self.pending.lock().await;
        for id in ids {
            pending.remove(id);
        }
    }

    async fn deliver_inbound_packet(
        &self,
        id: u16,
        bytes: Bytes,
    ) -> Result<(), SError> {
        let route = {
            let inbound_ids = self.inbound_ids.lock().await;
            inbound_ids
                .get(&id)
                .map(|route| (route.tx.clone(), route.dst.clone()))
        };

        if let Some((tx, dst)) = route {
            tx.send((bytes, dst)).await.map_err(|e| {
                SError::UDPSessionClosed(format!("UDP request channel closed: {e}"))
            })?;
            return Ok(());
        }

        let mut pending = self.pending.lock().await;
        if !pending.contains_key(&id)
            && pending.len() >= MAX_UDP_PENDING_IDS_PER_CONN
        {
            return Err(SError::UDPSessionClosed(format!(
                "too many pending UDP ids in one shadowquic connection: {}",
                pending.len()
            )));
        }

        let packets = pending.entry(id).or_default();
        if packets.len() >= MAX_UDP_PENDING_PACKETS_PER_ID {
            return Err(SError::UDPSessionClosed(format!(
                "too many pending UDP packets for id {id}: {}",
                packets.len()
            )));
        }
        packets.push(bytes);
        Ok(())
    }
}

struct ShadowQuicInboundDatagram {
    request_rx: mpsc::Receiver<(Bytes, SQAddr)>,
    response_tx: PollSender<(Bytes, SQAddr)>,
    source: SocketAddr,
    inbound_user: Option<String>,
}

impl fmt::Debug for ShadowQuicInboundDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowQuicInboundDatagram")
            .field("source", &self.source)
            .finish()
    }
}

impl Stream for ShadowQuicInboundDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.request_rx.poll_recv(cx).map(|item| {
            item.and_then(|(data, dst)| {
                let dst_addr = match to_clash_socks_addr(dst) {
                    Ok(addr) => addr,
                    Err(e) => {
                        warn!(
                            "shadowquic inbound dropped UDP packet with invalid destination: {e}"
                        );
                        return None;
                    }
                };
                Some(UdpPacket {
                    data: data.to_vec(),
                    src_addr: SocksAddr::Ip(self.source),
                    dst_addr,
                    inbound_user: self.inbound_user.clone(),
                })
            })
        })
    }
}

impl Sink<UdpPacket> for ShadowQuicInboundDatagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.response_tx.poll_ready_unpin(cx).map_err(new_io_error)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let src_addr = to_sq_socks_addr(item.src_addr)?;
        self.response_tx
            .start_send_unpin((item.data.into(), src_addr))
            .map_err(new_io_error)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.response_tx.poll_flush_unpin(cx).map_err(new_io_error)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

struct Unsplit<S, R> {
    send: S,
    recv: R,
}

impl<S, R> tokio::io::AsyncRead for Unsplit<S, R>
where
    S: AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl<S, R> tokio::io::AsyncWrite for Unsplit<S, R>
where
    S: AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}
