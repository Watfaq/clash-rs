use crate::{
    common::tls::DefaultTlsVerifier,
    proxy::{tuic::types::SocketAdderTrans, utils::new_udp_socket},
};
use anyhow::Result;
use arc_swap::ArcSwap;
use async_trait::async_trait;

use quinn::{
    EndpointConfig, TokioRuntime,
    congestion::{BbrConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
};
use tracing::debug;
use watfaq_state::Context;

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

impl DialWithConnector for watfaq_tuic::Handler {}

#[async_trait]
impl OutboundHandler for watfaq_tuic::Handler {
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
        ctx: ArcSwap<Context>,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        async {
            let conn = self.get_conn(&ctx.load(), &resolver, sess).await?;
            let dest = sess.destination.clone().into_tuic();
            let tuic_tcp = conn.connect_tcp(dest).await?;
            let s = ChainedStreamWrapper::new(tuic_tcp);
            s.append_to_chain(self.name()).await;
            Ok(Box::new(s))
        }
        .await
        .map_err(|e| {
            tracing::error!("{:?}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })?
    }

    async fn connect_datagram(
        &self,
        ctx: ArcSwap<Context>,
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
             certificate: Expired"
        ));
        Ok(())
    }
}
