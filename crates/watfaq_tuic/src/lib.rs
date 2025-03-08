mod compat;
mod handle_stream;
mod handle_task;
pub(crate) mod types;

use watfaq_error::Result;

use quinn::{
    EndpointConfig, TokioRuntime,
    congestion::{BbrConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
};
use tracing::debug;
use types::{ServerAddr, SocketAdderTrans, TuicClient};
use watfaq_config::OutboundCommonOptions;
use watfaq_resolver::AbstractResolver;
use watfaq_state::Context;
use watfaq_types::{Session, TargetAddr, UdpPacket};
use watfaq_utils::{DefaultTlsVerifier, which_stack_decision};

use std::{
    net::IpAddr,
    sync::{Arc, atomic::AtomicU16},
    time::Duration,
};

use uuid::Uuid;

use quinn::{
    ClientConfig as QuinnConfig, Endpoint as QuinnEndpoint,
    TransportConfig as QuinnTransportConfig, VarInt, congestion::CubicConfig,
};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

use self::types::{TuicConnection, UdpRelayMode, UdpSession};

pub use self::types::CongestionControl;

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

    pub common: OutboundCommonOptions,
    pub ip: Option<IpAddr>,

    /// not used
    #[allow(dead_code)]
    pub max_udp_relay_packet_size: u64,

    #[allow(dead_code)]
    pub sni: Option<String>,
}

pub struct Handler {
    pub opts: HandlerOptions,
    ep: OnceCell<TuicClient>,
    conn: AsyncMutex<Option<Arc<TuicConnection>>>,
    pub next_assoc_id: AtomicU16,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TUIC")
            .field("name", &self.opts.name)
            .finish()
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
        ctx: &Context,
        opts: HandlerOptions,
        resolver: &impl AbstractResolver,
        sess: &Session,
    ) -> Result<TuicClient> {
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
        let server = ServerAddr::new(opts.server.clone(), opts.port, opts.ip);
        let server_ip = server.resolve(resolver).await?;

        let stack = which_stack_decision(
            opts.common
                .interface
                .as_ref()
                .unwrap_or(&ctx.default_iface.load()),
            opts.common.stack_prefer.unwrap_or(ctx.stack_prefer),
            server_ip.into(),
        )
        .unwrap_or_default();
        // TODO allow override protector (when outbound specify interface/fwmark)
        let socket = ctx.protector.new_udp_socket(stack).await?;

        debug!("binding socket to: {:?}", socket.local_addr()?);

        let mut endpoint = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket.into_std()?,
            Arc::new(TokioRuntime),
        )?;

        endpoint.set_default_client_config(quinn_config);
        let endpoint = TuicClient {
            ep: endpoint,
            server,
            uuid: opts.uuid,
            password: Arc::from(
                opts.password.clone().into_bytes().into_boxed_slice(),
            ),
            udp_relay_mode: opts.udp_relay_mode,
            zero_rtt_handshake: opts.reduce_rtt,
            heartbeat: opts.heartbeat_interval,
            gc_interval: opts.gc_interval,
            gc_lifetime: opts.gc_lifetime,
            common: opts.common,
            ip: opts.ip,
        };

        Ok(endpoint)
    }

    pub async fn get_conn(
        &self,
        ctx: &Context,
        resolver: &impl AbstractResolver,
        sess: &Session,
    ) -> Result<Arc<TuicConnection>> {
        let endpoint = self
            .ep
            .get_or_try_init(|| {
                Self::init_endpoint(ctx, self.opts.clone(), resolver, sess)
            })
            .await?;

        let fut = async {
            let mut guard = self.conn.lock().await;
            if guard.is_none() {
                // init
                *guard = Some(endpoint.connect(ctx, resolver, false).await?);
            }
            let conn = guard.take().unwrap();
            let conn = if conn.check_open().is_err() {
                // reconnect
                endpoint.connect(ctx, resolver, true).await?
            } else {
                conn
            };
            *guard = Some(conn.clone());
            Ok(conn)
        };

        tokio::time::timeout(self.opts.request_timeout, fut).await?
    }
}

#[derive(Debug)]
struct TuicUdpOutbound {
    send_tx: tokio_util::sync::PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
}

impl TuicUdpOutbound {
    pub fn new(
        assoc_id: u16,
        conn: Arc<TuicConnection>,
        local_addr: TargetAddr,
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

#[cfg(all(test, feature = "docker-test"))]
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
             certificate: Expired"
        ));
        Ok(())
    }
}
