mod compat;
mod handle_stream;
mod handle_task;
pub(crate) mod types;

use crate::{
    common::tls::DefaultTlsVerifier,
    proxy::{tuic::types::SocketAdderTrans, utils::new_udp_socket},
};
use anyhow::Result;
use async_trait::async_trait;

use quinn::{
    EndpointConfig, TokioRuntime,
    congestion::{BbrConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
};
use tracing::debug;

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use uuid::Uuid;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    proxy::{
        DialWithConnector,
        tuic::types::{ServerAddr, TuicEndpoint},
    },
    session::Session,
};

use crate::session::SocksAddr as ClashSocksAddr;
use quinn::{
    ClientConfig as QuinnConfig, Endpoint as QuinnEndpoint,
    TransportConfig as QuinnTransportConfig, VarInt, congestion::CubicConfig,
};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

use self::types::{CongestionControl, TuicConnection, UdpRelayMode, UdpSession};

use super::{
    ConnectorType, HandlerCommonOptions, OutboundHandler, OutboundType,
    datagram::UdpPacket,
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
    pub skip_cert_verify: bool,

    #[allow(dead_code)]
    pub common_opts: HandlerCommonOptions,

    /// not used
    #[allow(dead_code)]
    pub max_udp_relay_packet_size: u64,
    #[allow(dead_code)]
    pub ip: Option<String>,
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
        sess: &Session,
    ) -> Result<TuicEndpoint> {
        let verifier = DefaultTlsVerifier::new(None, opts.skip_cert_verify);
        let mut crypto =
            rustls::client::ClientConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS13,
            ])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        // TODO(error-handling) if alpn not match the following error will be
        // throw: aborted by peer: the cryptographic handshake failed: error
        // 120: peer doesn't support any known protocol
        crypto.alpn_protocols.clone_from(&opts.alpn);
        crypto.enable_early_data = true;
        crypto.enable_sni = !opts.disable_sni;

        let mut quinn_config =
            QuinnConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
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
            if resolver.ipv6() {
                new_udp_socket(
                    Some((Ipv6Addr::UNSPECIFIED, 0).into()),
                    sess.iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                )
                .await?
            } else {
                new_udp_socket(
                    Some((Ipv4Addr::UNSPECIFIED, 0).into()),
                    None,
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
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
        sess: &Session,
    ) -> Result<Arc<TuicConnection>> {
        let endpoint = self
            .ep
            .get_or_try_init(|| {
                Self::init_endpoint(self.opts.clone(), resolver.clone(), sess)
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
        let conn = self.get_conn(&resolver, sess).await?;
        let dest = sess.destination.clone().into_tuic();
        let tuic_tcp = conn.connect_tcp(dest).await?;
        let s = ChainedStreamWrapper::new(tuic_tcp);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn do_connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedChainedDatagram> {
        let conn = self.get_conn(&resolver, sess).await?;
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
    pub fn new(
        assoc_id: u16,
        conn: Arc<TuicConnection>,
        local_addr: ClashSocksAddr,
    ) -> Self {
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

        Self {
            send_tx: tokio_util::sync::PollSender::new(send_tx),
            recv_rx,
        }
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use super::super::utils::test_utils::{
        consts::*, docker_runner::DockerTestRunner,
    };
    use crate::{
        proxy::utils::{
            GLOBAL_DIRECT_CONNECTOR,
            test_utils::{
                Suite, config_helper::test_config_base_dir,
                docker_runner::DockerTestRunnerBuilder, run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    use super::*;
    async fn get_tuic_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let conf = test_config_dir.join("tuic.json");
        let cert = test_config_dir.join("example.org.pem");
        let key = test_config_dir.join("example.org-key.pem");

        DockerTestRunnerBuilder::new()
            .image(IMAGE_TUIC)
            .mounts(&[
                (conf.to_str().unwrap(), "/etc/tuic/config.json"),
                (cert.to_str().unwrap(), "/opt/tuic/fullchain.pem"),
                (key.to_str().unwrap(), "/opt/tuic/privkey.pem"),
            ])
            .build()
            .await
    }

    const PORT: u16 = 10002;

    fn gen_options(skip_cert_verify: bool) -> anyhow::Result<HandlerOptions> {
        Ok(HandlerOptions {
            name: "test-tuic".to_owned(),
            server: LOCAL_ADDR.into(),
            port: PORT,
            common_opts: Default::default(),
            uuid: "00000000-0000-0000-0000-000000000001".parse()?,
            password: "passwd".into(),
            udp_relay_mode: UdpRelayMode::Native,
            disable_sni: true,
            alpn: vec!["h3".into()],
            heartbeat_interval: Duration::from_millis(3000),
            reduce_rtt: false,
            request_timeout: Duration::from_millis(4000),
            idle_timeout: Duration::from_millis(4000),
            congestion_controller: CongestionControl::Bbr,
            max_udp_relay_packet_size: 1500,
            max_open_stream: VarInt::from_u64(32)?,
            ip: None,
            skip_cert_verify,
            sni: Some("example.org".to_owned()),
            gc_interval: Duration::from_millis(3000),
            gc_lifetime: Duration::from_millis(15000),
            send_window: 8 * 1024 * 1024 * 2,
            receive_window: VarInt::from_u64(8 * 1024 * 1024)?,
        })
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_tuic_skip_cert_verify() -> anyhow::Result<()> {
        initialize();
        let opts = gen_options(true)?;

        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(handler, get_tuic_runner().await?, Suite::all())
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_tuic_cert_verify_expect_fail() -> anyhow::Result<()> {
        initialize();
        let opts = gen_options(false)?;

        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        let res = run_test_suites_and_cleanup(
            handler,
            get_tuic_runner().await?,
            Suite::all(),
        )
        .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains(
            "the cryptographic handshake failed: error 45: invalid peer \
             certificate: certificate expired"
        ));
        Ok(())
    }
}
