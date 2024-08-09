mod compat;
mod handle_stream;
mod handle_task;
pub(crate) mod types;

use crate::{
    impl_default_connector,
    proxy::{tuic::types::SocketAdderTrans, utils::new_udp_socket},
};
use anyhow::Result;
use axum::async_trait;

use quinn::{
    congestion::{BbrConfig, NewRenoConfig},
    EndpointConfig, TokioRuntime,
};
use tracing::debug;

use std::{
    net::{Ipv4Addr, Ipv6Addr},
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
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::tls::GLOBAL_ROOT_STORE,
    proxy::{
        tuic::types::{ServerAddr, TuicEndpoint},
        DialWithConnector,
    },
    session::Session,
};

use crate::session::SocksAddr as ClashSocksAddr;
use quinn::{
    congestion::CubicConfig, ClientConfig as QuinnConfig, Endpoint as QuinnEndpoint,
    TransportConfig as QuinnTransportConfig, VarInt,
};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

use rustls::client::ClientConfig as TlsConfig;

use self::types::{CongestionControl, TuicConnection, UdpRelayMode, UdpSession};

use super::{
    datagram::UdpPacket,
    utils::{get_outbound_interface, Interface, RemoteConnector},
    AnyOutboundDatagram, AnyOutboundHandler, CommonOption, ConnectorType,
    OutboundHandler, OutboundType,
};

#[derive(Debug, Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub udp_relay_mode: UdpRelayMode,
    pub disable_sni: bool,
    pub alpn: Vec<Vec<u8>>,
    pub heartbeat_interval: Duration,
    pub reduce_rtt: bool,
    pub request_timeout: Duration,
    pub idle_timeout: Duration,
    pub congestion_controller: CongestionControl,
    pub max_open_stream: VarInt,
    pub gc_interval: Duration,
    pub gc_lifetime: Duration,
    pub send_window: u64,
    pub receive_window: VarInt,

    pub common_opts: CommonOption,

    /// not used
    #[allow(dead_code)]
    pub max_udp_relay_packet_size: u64,
    #[allow(dead_code)]
    pub ip: Option<String>,
    #[allow(dead_code)]
    pub skip_cert_verify: bool,
    #[allow(dead_code)]
    pub sni: Option<String>,
}

pub struct Handler {
    opts: HandlerOptions,
    ep: OnceCell<TuicEndpoint>,
    conn: AsyncMutex<Option<Arc<TuicConnection>>>,
    next_assoc_id: AtomicU16,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuic")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tuic
    }

    async fn support_udp(&self) -> bool {
        true
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

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            ep: OnceCell::new(),
            conn: AsyncMutex::new(None),
            next_assoc_id: AtomicU16::new(0),
        }
    }

    async fn init_endpoint(
        opts: HandlerOptions,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<TuicEndpoint> {
        let mut crypto = TlsConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        // TODO(error-handling) if alpn not match the following error will be
        // throw: aborted by peer: the cryptographic handshake failed: error
        // 120: peer doesn't support any known protocol
        crypto.alpn_protocols.clone_from(&opts.alpn);
        crypto.enable_early_data = true;
        crypto.enable_sni = !opts.disable_sni;
        let mut quinn_config = QuinnConfig::new(Arc::new(crypto));
        let mut transport_config = QuinnTransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(opts.max_open_stream)
            .max_concurrent_uni_streams(opts.max_open_stream)
            .send_window(opts.send_window)
            .stream_receive_window(opts.receive_window)
            .max_idle_timeout(Some(opts.idle_timeout.try_into().unwrap()));
        match opts.congestion_controller {
            CongestionControl::Cubic => transport_config
                .congestion_controller_factory(Arc::new(CubicConfig::default())),
            CongestionControl::NewReno => transport_config
                .congestion_controller_factory(Arc::new(NewRenoConfig::default())),
            CongestionControl::Bbr => transport_config
                .congestion_controller_factory(Arc::new(BbrConfig::default())),
        };

        quinn_config.transport_config(Arc::new(transport_config));

        let socket = {
            let iface = get_outbound_interface();

            if resolver.ipv6() {
                new_udp_socket(
                    Some((Ipv6Addr::UNSPECIFIED, 0).into()).as_ref(),
                    iface.map(|x| Interface::Name(x.name.clone())).as_ref(),
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    None,
                )
                .await?
            } else {
                new_udp_socket(
                    Some((Ipv4Addr::UNSPECIFIED, 0).into()).as_ref(),
                    iface.map(|x| Interface::Name(x.name.clone())).as_ref(),
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    None,
                )
                .await?
            }
        };

        debug!("binding socket to: {:?}", socket.local_addr()?);

        let mut endpoint = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket.into_std()?,
            Arc::new(TokioRuntime),
        )?;

        endpoint.set_default_client_config(quinn_config);
        let endpoint = TuicEndpoint {
            ep: endpoint,
            server: ServerAddr::new(opts.server.clone(), opts.port, None),
            uuid: opts.uuid,
            password: Arc::from(
                opts.password.clone().into_bytes().into_boxed_slice(),
            ),
            udp_relay_mode: opts.udp_relay_mode,
            zero_rtt_handshake: opts.reduce_rtt,
            heartbeat: opts.heartbeat_interval,
            gc_interval: opts.gc_interval,
            gc_lifetime: opts.gc_lifetime,
        };

        Ok(endpoint)
    }

    async fn get_conn(
        &self,
        resolver: &ThreadSafeDNSResolver,
    ) -> Result<Arc<TuicConnection>> {
        let endpoint = self
            .ep
            .get_or_try_init(|| {
                Self::init_endpoint(self.opts.clone(), resolver.clone())
            })
            .await?;

        let fut = async {
            let mut guard = self.conn.lock().await;
            if guard.is_none() {
                // init
                *guard = Some(endpoint.connect(resolver, false).await?);
            }
            let conn = guard.take().unwrap();
            let conn = if conn.check_open().is_err() {
                // reconnect
                endpoint.connect(resolver, true).await?
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
        resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedChainedStream> {
        let conn = self.get_conn(&resolver).await?;
        let dest = sess.destination.clone().into_tuic();
        let tuic_tcp = conn.connect_tcp(dest).await?.compat();
        let s = ChainedStreamWrapper::new(tuic_tcp);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn do_connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedChainedDatagram> {
        let conn = self.get_conn(&resolver).await?;
        let assos_id = self.next_assoc_id.fetch_add(1, Ordering::SeqCst);
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
            tracing::info!(
                "[udp] [dissociate] closing UDP session [{assoc_id:#06x}]"
            );
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
