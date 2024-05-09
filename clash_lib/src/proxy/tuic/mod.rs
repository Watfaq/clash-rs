mod compat;
mod handle_stream;
mod handle_task;
pub(crate) mod types;

use crate::proxy::tuic::types::SocketAdderTrans;
use anyhow::Result;
use axum::async_trait;
use quinn::{EndpointConfig, TokioRuntime};
use std::net::SocketAddr;
use std::{
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use uuid::Uuid;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram, ChainedDatagramWrapper,
            ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::tls::GLOBAL_ROOT_STORE,
    proxy::tuic::types::{ServerAddr, TuicEndpoint},
    session::{Session, SocksAddr},
};

use crate::session::SocksAddr as ClashSocksAddr;
use quinn::ClientConfig as QuinnConfig;
use quinn::Endpoint as QuinnEndpoint;
use quinn::TransportConfig as QuinnTransportConfig;
use quinn::{congestion::CubicConfig, VarInt};
use tokio::sync::Mutex as AsyncMutex;

use rustls::client::ClientConfig as TlsConfig;

use self::types::{CongestionControl, TuicConnection, UdpSession};

use super::{
    datagram::UdpPacket, AnyOutboundDatagram, AnyOutboundHandler, AnyStream, OutboundHandler,
    OutboundType,
};

#[derive(Debug, Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub udp_relay_mode: String,
    pub disable_sni: bool,
    pub alpn: Vec<Vec<u8>>,
    pub heartbeat_interval: Duration,
    pub reduce_rtt: bool,
    pub request_timeout: Duration,
    pub congestion_controller: CongestionControl,
    pub max_udp_relay_packet_size: u64,
    pub max_open_stream: VarInt,
    pub gc_interval: Duration,
    pub gc_lifetime: Duration,
    pub send_window: u64,
    pub receive_window: VarInt,

    /// not used
    pub ip: Option<String>,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
}

pub struct Handler {
    opts: HandlerOptions,
    ep: TuicEndpoint,
    conn: AsyncMutex<Option<Arc<TuicConnection>>>,
    next_assoc_id: AtomicU16,
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tuic
    }

    async fn remote_addr(&self) -> Option<SocksAddr> {
        None
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn proxy_stream(
        &self,
        s: AnyStream,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        tracing::warn!("Proxy stream currently is direcrt connect");
        Ok(s)
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        self.do_connect_stream(sess, resolver).await.map_err(|e| {
            tracing::error!("{:?}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        self.do_connect_datagram(sess, resolver).await.map_err(|e| {
            tracing::error!("{:?}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }
}

impl Handler {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(opts: HandlerOptions) -> Result<AnyOutboundHandler, crate::Error> {
        let mut crypto = TlsConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        // TODO(error-handling) if alpn not match the following error will be throw: aborted by peer: the cryptographic handshake failed: error 120: peer doesn't support any known protocol
        crypto.alpn_protocols.clone_from(&opts.alpn);
        crypto.enable_early_data = true;
        crypto.enable_sni = !opts.disable_sni;
        let mut quinn_config = QuinnConfig::new(Arc::new(crypto));
        let mut quinn_transport_config = QuinnTransportConfig::default();
        quinn_transport_config
            .max_concurrent_bidi_streams(opts.max_open_stream)
            .max_concurrent_uni_streams(opts.max_open_stream)
            .send_window(opts.send_window)
            .stream_receive_window(opts.receive_window)
            .max_idle_timeout(None)
            .congestion_controller_factory(Arc::new(CubicConfig::default()));
        quinn_config.transport_config(Arc::new(quinn_transport_config));
        // Try to create an IPv4 socket as the placeholder first, if it fails, try IPv6.
        let socket =
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).or_else(|err| {
                UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).map_err(|_| err)
            })?;

        let mut endpoint = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )?;
        endpoint.set_default_client_config(quinn_config);
        let endpoint = TuicEndpoint {
            ep: endpoint,
            server: ServerAddr::new(opts.server.clone(), opts.port, None),
            uuid: opts.uuid,
            password: Arc::from(opts.password.clone().into_bytes().into_boxed_slice()),
            udp_relay_mode: types::UdpRelayMode::Native,
            zero_rtt_handshake: opts.reduce_rtt,
            heartbeat: opts.heartbeat_interval,
            gc_interval: opts.gc_interval,
            gc_lifetime: opts.gc_lifetime,
        };
        Ok(Arc::new(Self {
            opts,
            ep: endpoint,
            conn: AsyncMutex::new(None),
            next_assoc_id: AtomicU16::new(0),
        }))
    }
    async fn get_conn(&self) -> Result<Arc<TuicConnection>> {
        let fut = async {
            let mut guard = self.conn.lock().await;
            if guard.is_none() {
                // init
                *guard = Some(self.ep.connect().await?);
            }
            let conn = guard.take().unwrap();
            let conn = if conn.check_open().is_err() {
                // reconnect
                self.ep.connect().await?
            } else {
                conn
            };
            *guard = Some(conn.clone());
            Ok(conn)
        };
        tokio::time::timeout(self.opts.request_timeout, fut).await?
    }

    async fn do_connect_stream(
        &self,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedChainedStream> {
        let conn = self.get_conn().await?;
        let dest = sess.destination.clone().into_tuic();
        let tuic_tcp = conn.connect_tcp(dest).await?.compat();

        let s = ChainedStreamWrapper::new(tuic_tcp);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn do_connect_datagram(
        &self,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedChainedDatagram> {
        let conn = self.get_conn().await?;

        let assos_id = self.next_assoc_id.fetch_add(1, Ordering::Relaxed);
        let quic_udp = TuicDatagramOutbound::new(assos_id, conn, sess.source.into());
        let s = ChainedDatagramWrapper::new(quic_udp);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }
}

#[derive(Debug)]
struct TuicDatagramOutbound {
    send_tx: tokio_util::sync::PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
}

impl TuicDatagramOutbound {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        assoc_id: u16,
        conn: Arc<TuicConnection>,
        local_addr: ClashSocksAddr,
    ) -> AnyOutboundDatagram {
        // TODO not sure about the size of buffer
        let (send_tx, send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let udp_sessions = conn.udp_sessions.clone();
        tokio::spawn(async move {
            // capture vars
            let (mut send_rx, recv_tx) = (send_rx, recv_tx);
            udp_sessions.write().await.insert(
                assoc_id,
                UdpSession {
                    incoming: recv_tx,
                    local_addr,
                },
            );
            while let Some(next_send) = send_rx.recv().await {
                let res = conn
                    .outgoing_udp(
                        next_send.data.into(),
                        next_send.dst_addr.into_tuic(),
                        assoc_id,
                    )
                    .await;
                if res.is_err() {
                    break;
                }
            }
            // TuicDatagramOutbound dropped or outgoing_udp occurs error
            tracing::info!("[udp] [dissociate] closing UDP session [{assoc_id:#06x}]");
            _ = conn.dissociate(assoc_id).await;
            udp_sessions.write().await.remove(&assoc_id);
            anyhow::Ok(())
        });
        let s = Self {
            send_tx: tokio_util::sync::PollSender::new(send_tx),
            recv_rx,
        };
        Box::new(s)
    }
}
