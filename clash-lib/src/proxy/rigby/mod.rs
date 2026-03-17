mod uri;

pub use uri::RigbyUri;

use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType,
    datagram::UdpPacket,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    impl_default_connector,
    proxy::AnyOutboundDatagram,
    session::{Session, SocksAddr},
};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use rand::Rng as _;
use snow::{Builder, TransportState, params::NoiseParams};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, RwLock, mpsc},
};
use tokio_util::sync::PollSender;
use tracing::{debug, trace};

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROTOCOL_VERSION: u8 = 1;
const MAX_FRAME_PAYLOAD: usize = 1200;
const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(6);
const HANDSHAKE_MAX_SKEW: Duration = Duration::from_secs(120);
const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub server_static_pubkey: [u8; 32],
    pub client_private_key: Option<[u8; 32]>,
    pub sni: Option<String>,
    pub padding: bool,
    pub mux: bool,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
    conn: Mutex<Option<Arc<RigbyClientConnection>>>,
}

impl_default_connector!(Handler);

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rigby")
            .field("name", &self.opts.name)
            .field("server", &self.opts.server)
            .field("port", &self.opts.port)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
            conn: Mutex::new(None),
        }
    }

    async fn get_or_connect(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<Arc<RigbyClientConnection>> {
        let mut guard = self.conn.lock().await;
        if let Some(existing) = guard.as_ref()
            && !existing.is_closed()
        {
            return Ok(existing.clone());
        }

        let conn = Arc::new(
            RigbyClientConnection::connect(
                self.opts.clone(),
                sess,
                resolver,
                connector,
            )
            .await?,
        );
        *guard = Some(conn.clone());
        Ok(conn)
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Rigby
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let dialer = self.connector.read().await;
        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }
        self.connect_stream_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let dialer = self.connector.read().await;
        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }
        self.connect_datagram_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        let conn = self.get_or_connect(sess, resolver, connector).await?;
        let stream = conn.open_stream(sess.destination.clone()).await?;
        let chained = ChainedStreamWrapper::new(stream);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let conn = self.get_or_connect(sess, resolver, connector).await?;
        let dgram = conn
            .open_datagram(sess.source.into(), sess.destination.clone())
            .await?;
        let chained = ChainedDatagramWrapper::new(dgram);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameKind {
    Open = 0x01,
    Data = 0x02,
    Close = 0x03,
    Datagram = 0x04,
    Ping = 0x05,
    Pong = 0x06,
}

impl TryFrom<u8> for FrameKind {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Open),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Close),
            0x04 => Ok(Self::Datagram),
            0x05 => Ok(Self::Ping),
            0x06 => Ok(Self::Pong),
            _ => Err(io::Error::other("invalid frame kind")),
        }
    }
}

#[derive(Clone, Debug)]
struct OutgoingFrame {
    kind: FrameKind,
    stream_id: u16,
    target: Option<SocksAddr>,
    payload: Vec<u8>,
}

impl OutgoingFrame {
    fn open(stream_id: u16, target: SocksAddr) -> Self {
        Self {
            kind: FrameKind::Open,
            stream_id,
            target: Some(target),
            payload: Vec::new(),
        }
    }

    fn data(stream_id: u16, payload: Vec<u8>) -> Self {
        Self {
            kind: FrameKind::Data,
            stream_id,
            target: None,
            payload,
        }
    }

    fn close(stream_id: u16) -> Self {
        Self {
            kind: FrameKind::Close,
            stream_id,
            target: None,
            payload: Vec::new(),
        }
    }

    fn datagram(stream_id: u16, target: SocksAddr, payload: Vec<u8>) -> Self {
        Self {
            kind: FrameKind::Datagram,
            stream_id,
            target: Some(target),
            payload,
        }
    }

    fn ping() -> Self {
        Self {
            kind: FrameKind::Ping,
            stream_id: 0,
            target: None,
            payload: Vec::new(),
        }
    }

    fn pong() -> Self {
        Self {
            kind: FrameKind::Pong,
            stream_id: 0,
            target: None,
            payload: Vec::new(),
        }
    }
}

struct DecodedPacket {
    seq: u32,
    ack: u32,
    ack_bits: u32,
    frame: OutgoingFrame,
}

#[derive(Default)]
struct RecvWindow {
    initialized: bool,
    latest: u32,
    bitmap: u32,
}

impl RecvWindow {
    fn observe(&mut self, seq: u32) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.latest = seq;
            self.bitmap = 0;
            return false;
        }

        if seq > self.latest {
            let diff = seq - self.latest;
            if diff >= 32 {
                self.bitmap = 0;
            } else {
                self.bitmap <<= diff;
                self.bitmap |= 1u32 << (diff - 1);
            }
            self.latest = seq;
            return false;
        }

        let diff = self.latest - seq;
        if diff == 0 || diff > 32 {
            return true;
        }

        let bit = 1u32 << (diff - 1);
        if self.bitmap & bit != 0 {
            true
        } else {
            self.bitmap |= bit;
            false
        }
    }

    fn ack_tuple(&self) -> (u32, u32) {
        if self.initialized {
            (self.latest, self.bitmap)
        } else {
            (0, 0)
        }
    }
}

struct ClientDatagramSession {
    incoming: mpsc::Sender<UdpPacket>,
    local_addr: SocksAddr,
}

pub struct RigbyClientConnection {
    outgoing: mpsc::Sender<OutgoingFrame>,
    streams: Arc<RwLock<HashMap<u16, mpsc::Sender<Vec<u8>>>>>,
    datagrams: Arc<RwLock<HashMap<u16, ClientDatagramSession>>>,
    next_stream_id: AtomicU16,
    closed: Arc<AtomicBool>,
    mux: bool,
}

impl RigbyClientConnection {
    async fn connect(
        opts: HandlerOptions,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<Self> {
        let destination = SocksAddr::try_from((opts.server.clone(), opts.port))
            .map_err(|e| io::Error::other(e.to_string()))?;
        let mut datagram = connector
            .connect_datagram(
                resolver,
                None,
                destination.clone(),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let (mut sink, mut stream) = datagram.split();

        let params = NoiseParams::from_str(NOISE_PATTERN)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let local_private = opts
            .client_private_key
            .unwrap_or_else(random_x25519_private_key);
        let mut hs = Builder::new(params)
            .local_private_key(&local_private)
            .remote_public_key(&opts.server_static_pubkey)
            .build_initiator()
            .map_err(|e| io::Error::other(e.to_string()))?;

        let hs_payload = build_handshake_payload(opts.sni.as_deref(), opts.padding);
        let mut hs_msg = vec![0u8; 2048];
        let hs_len = hs
            .write_message(&hs_payload, &mut hs_msg)
            .map_err(|e| io::Error::other(e.to_string()))?;
        sink.send(UdpPacket::new(
            hs_msg[..hs_len].to_vec(),
            SocksAddr::any_ipv4(),
            destination.clone(),
        ))
        .await?;

        let response = tokio::time::timeout(CLIENT_HANDSHAKE_TIMEOUT, stream.next())
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "rigby handshake timeout")
            })?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "rigby handshake eof")
            })?;

        let mut hs_buf = vec![0u8; 2048];
        hs.read_message(&response.data, &mut hs_buf)
            .map_err(|e| io::Error::other(format!("rigby handshake failed: {e}")))?;
        let mut transport = hs
            .into_transport_mode()
            .map_err(|e| io::Error::other(e.to_string()))?;

        let streams: Arc<RwLock<HashMap<u16, mpsc::Sender<Vec<u8>>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let datagrams: Arc<RwLock<HashMap<u16, ClientDatagramSession>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let (outgoing, mut outgoing_rx) = mpsc::channel::<OutgoingFrame>(256);
        let outgoing_control = outgoing.clone();
        let streams_for_task = streams.clone();
        let datagrams_for_task = datagrams.clone();
        let closed_for_task = closed.clone();
        let destination_for_send = destination.clone();
        let padding = opts.padding;

        tokio::spawn(async move {
            let mut send_seq = 1u32;
            let mut recv_window = RecvWindow::default();
            let mut keepalive = tokio::time::interval(Duration::from_secs(25));

            loop {
                tokio::select! {
                    maybe_frame = outgoing_rx.recv() => {
                        let Some(frame) = maybe_frame else { break };
                        if let Err(e) = send_encrypted_frame(
                            &mut sink,
                            &mut transport,
                            &destination_for_send,
                            &mut send_seq,
                            &recv_window,
                            &frame,
                            padding,
                        ).await {
                            trace!("rigby send loop ended: {e}");
                            break;
                        }
                    }
                    maybe_pkt = stream.next() => {
                        let Some(pkt) = maybe_pkt else { break };
                        let decoded = match decrypt_packet(&mut transport, &pkt.data) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let duplicated = recv_window.observe(decoded.seq);
                        if duplicated {
                            continue;
                        }
                        trace!("rigby recv ack={} ack_bits={:#x}", decoded.ack, decoded.ack_bits);
                        match decoded.frame.kind {
                            FrameKind::Data => {
                                let tx = streams_for_task
                                    .read().await
                                    .get(&decoded.frame.stream_id)
                                    .cloned();
                                if let Some(tx) = tx {
                                    let _ = tx.send(decoded.frame.payload).await;
                                }
                            }
                            FrameKind::Close => {
                                streams_for_task.write().await.remove(&decoded.frame.stream_id);
                                datagrams_for_task.write().await.remove(&decoded.frame.stream_id);
                            }
                            FrameKind::Datagram => {
                                let target = match decoded.frame.target {
                                    Some(v) => v,
                                    None => continue,
                                };
                                if let Some(session) = datagrams_for_task
                                    .read().await
                                    .get(&decoded.frame.stream_id)
                                {
                                    let pkt = UdpPacket::new(
                                        decoded.frame.payload,
                                        session.local_addr.clone(),
                                        target,
                                    );
                                    let _ = session.incoming.send(pkt).await;
                                }
                            }
                            FrameKind::Ping => {
                                let _ = outgoing_control.try_send(OutgoingFrame::pong());
                            }
                            FrameKind::Open | FrameKind::Pong => {}
                        }
                    }
                    _ = keepalive.tick() => {
                        let _ = outgoing_control.try_send(OutgoingFrame::ping());
                    }
                }
            }

            closed_for_task.store(true, Ordering::Release);
            streams_for_task.write().await.clear();
            datagrams_for_task.write().await.clear();
        });

        Ok(Self {
            outgoing,
            streams,
            datagrams,
            next_stream_id: AtomicU16::new(1),
            closed,
            mux: opts.mux,
        })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    async fn send_frame(&self, frame: OutgoingFrame) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "rigby connection closed",
            ));
        }
        self.outgoing.send(frame).await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "rigby send queue closed")
        })
    }

    async fn remove_stream(&self, stream_id: u16) {
        self.streams.write().await.remove(&stream_id);
    }

    async fn remove_datagram(&self, stream_id: u16) {
        self.datagrams.write().await.remove(&stream_id);
    }

    fn alloc_stream_id(&self) -> u16 {
        let step = if self.mux { 1 } else { 2 };
        self.next_stream_id.fetch_add(step, Ordering::Relaxed)
    }

    async fn open_stream(
        self: &Arc<Self>,
        target: SocksAddr,
    ) -> io::Result<AnyStream> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "rigby connection closed",
            ));
        }

        let stream_id = self.alloc_stream_id();
        let (incoming_tx, mut incoming_rx) = mpsc::channel::<Vec<u8>>(64);
        self.streams.write().await.insert(stream_id, incoming_tx);
        self.send_frame(OutgoingFrame::open(stream_id, target))
            .await?;

        let (app_end, rigby_end) = tokio::io::duplex(64 * 1024);
        let (mut rigby_reader, mut rigby_writer) = tokio::io::split(rigby_end);
        let writer_conn = self.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; MAX_FRAME_PAYLOAD];
            loop {
                match rigby_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if writer_conn
                            .send_frame(OutgoingFrame::data(
                                stream_id,
                                buf[..n].to_vec(),
                            ))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = writer_conn
                .send_frame(OutgoingFrame::close(stream_id))
                .await;
            writer_conn.remove_stream(stream_id).await;
        });

        let reader_conn = self.clone();
        tokio::spawn(async move {
            while let Some(chunk) = incoming_rx.recv().await {
                if rigby_writer.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = rigby_writer.shutdown().await;
            reader_conn.remove_stream(stream_id).await;
        });

        Ok(Box::new(app_end))
    }

    async fn open_datagram(
        self: &Arc<Self>,
        local_addr: SocksAddr,
        default_target: SocksAddr,
    ) -> io::Result<RigbyDatagramOutbound> {
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "rigby connection closed",
            ));
        }

        let stream_id = self.alloc_stream_id();
        let (send_tx, mut send_rx) = mpsc::channel::<UdpPacket>(64);
        let (recv_tx, recv_rx) = mpsc::channel::<UdpPacket>(64);
        self.datagrams.write().await.insert(
            stream_id,
            ClientDatagramSession {
                incoming: recv_tx,
                local_addr,
            },
        );

        let conn = self.clone();
        tokio::spawn(async move {
            while let Some(pkt) = send_rx.recv().await {
                let target = if is_unspecified_target(&pkt.dst_addr) {
                    default_target.clone()
                } else {
                    pkt.dst_addr.clone()
                };
                if conn
                    .send_frame(OutgoingFrame::datagram(stream_id, target, pkt.data))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            conn.remove_datagram(stream_id).await;
        });

        Ok(RigbyDatagramOutbound {
            send_tx: PollSender::new(send_tx),
            recv_rx,
        })
    }
}

#[derive(Debug)]
struct RigbyDatagramOutbound {
    send_tx: PollSender<UdpPacket>,
    recv_rx: mpsc::Receiver<UdpPacket>,
}

impl Sink<UdpPacket> for RigbyDatagramOutbound {
    type Error = io::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|e| new_io_error(format!("{e:?}")))
    }

    fn start_send(
        mut self: std::pin::Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|e| new_io_error(format!("{e:?}")))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|e| new_io_error(format!("{e:?}")))
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|e| new_io_error(format!("{e:?}")))
    }
}

impl Stream for RigbyDatagramOutbound {
    type Item = UdpPacket;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}

fn random_x25519_private_key() -> [u8; 32] {
    let mut out = [0u8; 32];
    rand::rng().fill(&mut out);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn build_handshake_payload(sni: Option<&str>, padding: bool) -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(128);
    payload.put_u64(now_millis());
    let mut nonce = [0u8; 16];
    rand::rng().fill(&mut nonce);
    payload.put_slice(&nonce);

    if let Some(sni) = sni {
        let bytes = sni.as_bytes();
        let len = bytes.len().min(u8::MAX as usize);
        payload.put_u8(len as u8);
        payload.put_slice(&bytes[..len]);
    } else {
        payload.put_u8(0);
    }

    if padding {
        let mut rng = rand::rng();
        let pad_len = rng.random_range(16..=96);
        let mut pad = vec![0u8; pad_len];
        rng.fill(pad.as_mut_slice());
        payload.put_slice(&pad);
    }
    payload.to_vec()
}

fn validate_handshake_payload(payload: &[u8]) -> Option<[u8; 16]> {
    if payload.len() < 24 {
        return None;
    }
    let ts = u64::from_be_bytes(payload.get(..8)?.try_into().ok()?);
    if now_millis().abs_diff(ts) > HANDSHAKE_MAX_SKEW.as_millis() as u64 {
        return None;
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(payload.get(8..24)?);
    Some(nonce)
}

fn encode_socks_addr(addr: &SocksAddr) -> Vec<u8> {
    let mut out = BytesMut::new();
    addr.write_buf(&mut out);
    out.to_vec()
}

fn decode_socks_addr(bytes: &[u8]) -> io::Result<SocksAddr> {
    SocksAddr::peek_read(bytes)
}

fn encode_plain_packet(
    seq: u32,
    ack: u32,
    ack_bits: u32,
    frame: &OutgoingFrame,
    padding: bool,
) -> io::Result<Vec<u8>> {
    let target_bytes = frame
        .target
        .as_ref()
        .map(encode_socks_addr)
        .unwrap_or_default();
    if target_bytes.len() > u16::MAX as usize {
        return Err(io::Error::other("target too large"));
    }
    if frame.payload.len() > u16::MAX as usize {
        return Err(io::Error::other("payload too large"));
    }

    let pad_len = if padding {
        rand::rng().random_range(0..=64)
    } else {
        0
    };
    let mut out = BytesMut::with_capacity(
        1 + 4
            + 4
            + 4
            + 1
            + 2
            + 2
            + 2
            + 2
            + target_bytes.len()
            + frame.payload.len()
            + pad_len,
    );
    out.put_u8(PROTOCOL_VERSION);
    out.put_u32(seq);
    out.put_u32(ack);
    out.put_u32(ack_bits);
    out.put_u8(frame.kind as u8);
    out.put_u16(frame.stream_id);
    out.put_u16(target_bytes.len() as u16);
    out.put_u16(frame.payload.len() as u16);
    out.put_u16(pad_len as u16);
    out.put_slice(&target_bytes);
    out.put_slice(&frame.payload);
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        rand::rng().fill(pad.as_mut_slice());
        out.put_slice(&pad);
    }
    Ok(out.to_vec())
}

fn decode_plain_packet(buf: &[u8]) -> io::Result<DecodedPacket> {
    let mut cur = std::io::Cursor::new(buf);
    if cur.remaining() < (1 + 4 + 4 + 4 + 1 + 2 + 2 + 2 + 2) {
        return Err(io::Error::other("short packet"));
    }
    let version = cur.get_u8();
    if version != PROTOCOL_VERSION {
        return Err(io::Error::other("unsupported packet version"));
    }
    let seq = cur.get_u32();
    let ack = cur.get_u32();
    let ack_bits = cur.get_u32();
    let kind = FrameKind::try_from(cur.get_u8())?;
    let stream_id = cur.get_u16();
    let target_len = cur.get_u16() as usize;
    let payload_len = cur.get_u16() as usize;
    let pad_len = cur.get_u16() as usize;
    if cur.remaining() < target_len + payload_len + pad_len {
        return Err(io::Error::other("invalid packet lengths"));
    }

    let mut target = vec![0u8; target_len];
    cur.copy_to_slice(&mut target);
    let mut payload = vec![0u8; payload_len];
    cur.copy_to_slice(&mut payload);
    if pad_len > 0 {
        cur.advance(pad_len);
    }

    Ok(DecodedPacket {
        seq,
        ack,
        ack_bits,
        frame: OutgoingFrame {
            kind,
            stream_id,
            target: if target.is_empty() {
                None
            } else {
                Some(decode_socks_addr(&target)?)
            },
            payload,
        },
    })
}

fn decrypt_packet(
    transport: &mut TransportState,
    encrypted: &[u8],
) -> io::Result<DecodedPacket> {
    let mut plaintext = vec![0u8; encrypted.len() + 32];
    let n = transport
        .read_message(encrypted, &mut plaintext)
        .map_err(|e| io::Error::other(e.to_string()))?;
    decode_plain_packet(&plaintext[..n])
}

async fn send_encrypted_frame<S>(
    sink: &mut S,
    transport: &mut TransportState,
    destination: &SocksAddr,
    send_seq: &mut u32,
    recv_window: &RecvWindow,
    frame: &OutgoingFrame,
    padding: bool,
) -> io::Result<()>
where
    S: Sink<UdpPacket, Error = io::Error> + Unpin,
{
    let (ack, ack_bits) = recv_window.ack_tuple();
    let plain = encode_plain_packet(*send_seq, ack, ack_bits, frame, padding)?;
    *send_seq = send_seq.wrapping_add(1);

    let mut encrypted = vec![0u8; plain.len() + 64];
    let n = transport
        .write_message(&plain, &mut encrypted)
        .map_err(|e| io::Error::other(e.to_string()))?;
    sink.send(UdpPacket::new(
        encrypted[..n].to_vec(),
        SocksAddr::any_ipv4(),
        destination.clone(),
    ))
    .await
}

async fn send_encrypted_to_socket(
    socket: &UdpSocket,
    transport: &mut TransportState,
    destination: &SocksAddr,
    send_seq: &mut u32,
    recv_window: &RecvWindow,
    frame: &OutgoingFrame,
    padding: bool,
) -> io::Result<()> {
    let (ack, ack_bits) = recv_window.ack_tuple();
    let plain = encode_plain_packet(*send_seq, ack, ack_bits, frame, padding)?;
    *send_seq = send_seq.wrapping_add(1);

    let mut encrypted = vec![0u8; plain.len() + 64];
    let n = transport
        .write_message(&plain, &mut encrypted)
        .map_err(|e| io::Error::other(e.to_string()))?;

    let dst = match destination {
        SocksAddr::Ip(ip) => *ip,
        SocksAddr::Domain(_, _) => {
            return Err(io::Error::other(
                "server destination must be a resolved socket address",
            ));
        }
    };
    socket.send_to(&encrypted[..n], dst).await?;
    Ok(())
}

fn is_unspecified_target(target: &SocksAddr) -> bool {
    match target {
        SocksAddr::Ip(addr) => addr.port() == 0 || addr.ip().is_unspecified(),
        SocksAddr::Domain(host, port) => host.trim().is_empty() || *port == 0,
    }
}

/// UDP server component with silent-drop behavior for invalid probes/handshakes.
#[derive(Clone)]
pub struct RigbyServerConfig {
    pub bind_addr: SocketAddr,
    pub server_static_private_key: [u8; 32],
    pub padding: bool,
}

pub struct RigbyServer {
    cfg: RigbyServerConfig,
}

impl RigbyServer {
    pub fn new(cfg: RigbyServerConfig) -> Self {
        Self { cfg }
    }

    pub async fn run(self) -> io::Result<()> {
        let socket = UdpSocket::bind(self.cfg.bind_addr).await?;
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<ServerOutbound>(1024);
        let mut replay_guard: HashMap<[u8; 16], Instant> = HashMap::new();
        let mut peers: HashMap<SocketAddr, ServerPeer> = HashMap::new();
        let mut cleanup = tokio::time::interval(Duration::from_secs(30));
        let mut recv_buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                recv = socket.recv_from(&mut recv_buf) => {
                    let (n, addr) = match recv {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let incoming = &recv_buf[..n];

                    if let Some(peer) = peers.get_mut(&addr) {
                        let decoded = match decrypt_packet(&mut peer.transport, incoming) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        peer.last_seen = Instant::now();
                        if peer.recv_window.observe(decoded.seq) {
                            continue;
                        }
                        trace!("rigby server recv ack={} ack_bits={:#x}", decoded.ack, decoded.ack_bits);
                        match decoded.frame.kind {
                            FrameKind::Open => {
                                let Some(target) = decoded.frame.target else { continue };
                                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
                                peer.streams.insert(decoded.frame.stream_id, tx);
                                let upstream = match connect_target(&target).await {
                                    Ok(s) => s,
                                    Err(_) => {
                                        let _ = outgoing_tx.send(ServerOutbound {
                                            peer: addr,
                                            frame: OutgoingFrame::close(decoded.frame.stream_id),
                                        }).await;
                                        continue;
                                    }
                                };
                                let (mut upstream_r, mut upstream_w) = tokio::io::split(upstream);
                                let out_close = outgoing_tx.clone();
                                let out_data = outgoing_tx.clone();
                                let sid = decoded.frame.stream_id;
                                tokio::spawn(async move {
                                    while let Some(chunk) = rx.recv().await {
                                        if upstream_w.write_all(&chunk).await.is_err() {
                                            break;
                                        }
                                    }
                                    let _ = upstream_w.shutdown().await;
                                    let _ = out_close.send(ServerOutbound {
                                        peer: addr,
                                        frame: OutgoingFrame::close(sid),
                                    }).await;
                                });
                                tokio::spawn(async move {
                                    let mut buf = [0u8; MAX_FRAME_PAYLOAD];
                                    loop {
                                        match upstream_r.read(&mut buf).await {
                                            Ok(0) => break,
                                            Ok(read_n) => {
                                                if out_data.send(ServerOutbound {
                                                    peer: addr,
                                                    frame: OutgoingFrame::data(sid, buf[..read_n].to_vec()),
                                                }).await.is_err() {
                                                    return;
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                    let _ = out_data.send(ServerOutbound {
                                        peer: addr,
                                        frame: OutgoingFrame::close(sid),
                                    }).await;
                                });
                            }
                            FrameKind::Data => {
                                if let Some(tx) = peer.streams.get(&decoded.frame.stream_id).cloned() {
                                    let _ = tx.send(decoded.frame.payload).await;
                                }
                            }
                            FrameKind::Close => {
                                peer.streams.remove(&decoded.frame.stream_id);
                            }
                            FrameKind::Datagram => {
                                let Some(target) = decoded.frame.target else { continue };
                                let payload = decoded.frame.payload;
                                let sid = decoded.frame.stream_id;
                                let out = outgoing_tx.clone();
                                tokio::spawn(async move {
                                    let Ok(target_addr) = resolve_socks_addr(&target).await else { return };
                                    let bind = if target_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                                    let Ok(udp) = UdpSocket::bind(bind).await else { return };
                                    if udp.send_to(&payload, target_addr).await.is_err() {
                                        return;
                                    }
                                    let mut udp_buf = vec![0u8; 65535];
                                    if let Ok(Ok((rn, src))) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut udp_buf)).await {
                                        let _ = out.send(ServerOutbound {
                                            peer: addr,
                                            frame: OutgoingFrame::datagram(sid, src.into(), udp_buf[..rn].to_vec()),
                                        }).await;
                                    }
                                });
                            }
                            FrameKind::Ping => {
                                let _ = outgoing_tx.send(ServerOutbound {
                                    peer: addr,
                                    frame: OutgoingFrame::pong(),
                                }).await;
                            }
                            FrameKind::Pong => {}
                        }
                        continue;
                    }

                    let Ok((mut transport, response)) = server_handshake(
                        incoming,
                        &self.cfg,
                        &mut replay_guard,
                    ) else {
                        continue;
                    };

                    let _ = socket.send_to(&response, addr).await;
                    peers.insert(addr, ServerPeer {
                        transport,
                        send_seq: 1,
                        recv_window: RecvWindow::default(),
                        streams: HashMap::new(),
                        last_seen: Instant::now(),
                    });
                }
                Some(to_send) = outgoing_rx.recv() => {
                    let Some(peer) = peers.get_mut(&to_send.peer) else { continue };
                    let dst: SocksAddr = to_send.peer.into();
                    if send_encrypted_to_socket(
                        &socket,
                        &mut peer.transport,
                        &dst,
                        &mut peer.send_seq,
                        &peer.recv_window,
                        &to_send.frame,
                        self.cfg.padding,
                    )
                    .await
                    .is_err()
                    {
                        peers.remove(&to_send.peer);
                    }
                }
                _ = cleanup.tick() => {
                    let now = Instant::now();
                    replay_guard.retain(|_, seen| now.duration_since(*seen) <= Duration::from_secs(300));
                    peers.retain(|_, peer| now.duration_since(peer.last_seen) <= SERVER_IDLE_TIMEOUT);
                }
            }
        }
    }
}

struct ServerPeer {
    transport: TransportState,
    send_seq: u32,
    recv_window: RecvWindow,
    streams: HashMap<u16, mpsc::Sender<Vec<u8>>>,
    last_seen: Instant,
}

struct ServerOutbound {
    peer: SocketAddr,
    frame: OutgoingFrame,
}

async fn connect_target(target: &SocksAddr) -> io::Result<TcpStream> {
    let addr = resolve_socks_addr(target).await?;
    TcpStream::connect(addr).await
}

async fn resolve_socks_addr(target: &SocksAddr) -> io::Result<SocketAddr> {
    match target {
        SocksAddr::Ip(addr) => Ok(*addr),
        SocksAddr::Domain(host, port) => {
            let mut resolved = tokio::net::lookup_host((host.as_str(), *port))
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            resolved
                .next()
                .ok_or_else(|| io::Error::other("failed to resolve target"))
        }
    }
}

fn server_handshake(
    packet: &[u8],
    cfg: &RigbyServerConfig,
    replay_guard: &mut HashMap<[u8; 16], Instant>,
) -> io::Result<(TransportState, Vec<u8>)> {
    let params = NoiseParams::from_str(NOISE_PATTERN)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut hs = Builder::new(params)
        .local_private_key(&cfg.server_static_private_key)
        .build_responder()
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mut payload = vec![0u8; 2048];
    let n = hs
        .read_message(packet, &mut payload)
        .map_err(|_| io::Error::other("invalid handshake"))?;

    let nonce = validate_handshake_payload(&payload[..n])
        .ok_or_else(|| io::Error::other("invalid handshake payload"))?;
    if replay_guard.contains_key(&nonce) {
        return Err(io::Error::other("replayed handshake"));
    }
    replay_guard.insert(nonce, Instant::now());

    let mut response_payload = vec![0u8; 24];
    rand::rng().fill(response_payload.as_mut_slice());
    if cfg.padding {
        let pad_len = rand::rng().random_range(8..=64);
        let mut pad = vec![0u8; pad_len];
        rand::rng().fill(pad.as_mut_slice());
        response_payload.extend_from_slice(&pad);
    }
    let mut response = vec![0u8; 2048];
    let rn = hs
        .write_message(&response_payload, &mut response)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let transport = hs
        .into_transport_mode()
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok((transport, response[..rn].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_codec_roundtrip() {
        let frame = OutgoingFrame::datagram(
            7,
            SocksAddr::from((std::net::Ipv4Addr::new(1, 1, 1, 1), 53)),
            b"hello".to_vec(),
        );
        let encoded = encode_plain_packet(9, 8, 0xff, &frame, true).unwrap();
        let decoded = decode_plain_packet(&encoded).unwrap();
        assert_eq!(decoded.seq, 9);
        assert_eq!(decoded.ack, 8);
        assert_eq!(decoded.frame.stream_id, 7);
        assert_eq!(decoded.frame.payload, b"hello");
    }

    #[test]
    fn handshake_payload_validation() {
        let payload = build_handshake_payload(Some("example.com"), true);
        assert!(validate_handshake_payload(&payload).is_some());
    }
}
