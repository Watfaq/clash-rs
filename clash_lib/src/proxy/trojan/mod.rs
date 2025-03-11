use std::{io, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tracing::debug;
use watfaq_config::OutboundCommonOptions;
use watfaq_utils::TargetAddrExt;

use crate::{
    app::dispatcher::{
        BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
        ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
    },
    common::utils,
    session::Session,
};

use self::datagram::OutboundDatagramTrojan;
use watfaq_error::Result;

use super::{
    AbstractOutboundHandler, AnyStream, ConnectorType,
    OutboundType,
    transport::Transport,
    utils::{GLOBAL_DIRECT_CONNECTOR, AbstractDialer},
};

mod datagram;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: OutboundCommonOptions,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub udp: bool,
    // might support shadow-tls?
    pub tls: Option<Box<dyn Transport>>,
    pub transport: Option<Box<dyn Transport>>,
}

pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::Mutex<Option<Arc<dyn AbstractDialer>>>,
}


impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trojan")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: tokio::sync::Mutex::new(None),
        }
    }

    /// TCP: 0x01,
    /// UDP: 0x03,
    async fn inner_proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        udp: bool,
    ) -> io::Result<AnyStream> {
        let s = if let Some(tls_client) = self.opts.tls.as_ref() {
            tls_client.proxy_stream(s).await?
        } else {
            s
        };

        let mut s = if let Some(transport) = self.opts.transport.as_ref() {
            transport.proxy_stream(s).await?
        } else {
            s
        };

        let mut buf = BytesMut::new();
        let password = Sha224::digest(self.opts.password.as_bytes());
        let password = utils::encode_hex(&password[..]);
        buf.put_slice(password.as_bytes());
        buf.put_slice(b"\r\n");
        buf.put_u8(if udp { 0x03 } else { 0x01 });
        sess.destination.write_buf(&mut buf);
        buf.put_slice(b"\r\n");
        s.write_all(&buf).await?;

        Ok(s)
    }
}

#[async_trait]
impl AbstractOutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Trojan
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(&self, sess: &Session) -> Result<BoxedChainedStream> {
        let dialer = self.connector.lock().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_stream_with_connector(
            sess,
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
    ) -> Result<BoxedChainedDatagram> {
        let dialer = self.connector.lock().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_datagram_with_connector(
            sess,
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
        connector: &dyn AbstractDialer,
    ) -> Result<BoxedChainedStream> {
        let stream = connector
            .connect_stream(self.opts.server.as_str(), self.opts.port)
            .await?;

        let s = self.inner_proxy_stream(stream, sess, false).await?;
        let chained = ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        connector: &dyn AbstractDialer,
    ) -> Result<BoxedChainedDatagram> {
        let stream = connector
            .connect_stream(self.opts.server.as_str(), self.opts.port)
            .await?;

        let stream = self.inner_proxy_stream(stream, sess, true).await?;

        let d = OutboundDatagramTrojan::new(stream, sess.destination.clone());

        let chained = ChainedDatagramWrapper::new(d);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    fn support_dialer(&self) -> Option<&str> {
        self.opts.common_opts.dialer.as_deref()
    }

    async fn register_connector(&self, connector: Arc<dyn AbstractDialer>) {
        let mut m = self.connector.lock().await;
        *m = Some(connector);
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use std::collections::HashMap;

    use crate::proxy::{
        transport,
        utils::test_utils::{
            Suite,
            config_helper::test_config_base_dir,
            consts::*,
            docker_runner::{DockerTestRunner, DockerTestRunnerBuilder},
            run_test_suites_and_cleanup,
        },
    };

    use super::*;

    async fn get_ws_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let trojan_conf = test_config_dir.join("trojan-ws.json");
        let trojan_cert = test_config_dir.join("example.org.pem");
        let trojan_key = test_config_dir.join("example.org-key.pem");

        DockerTestRunnerBuilder::new()
            .image(IMAGE_TROJAN_GO)
            .mounts(&[
                (trojan_conf.to_str().unwrap(), "/etc/trojan-go/config.json"),
                (trojan_cert.to_str().unwrap(), "/fullchain.pem"),
                (trojan_key.to_str().unwrap(), "/privkey.pem"),
            ])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_trojan_ws() -> anyhow::Result<()> {
        let span = tracing::info_span!("test_trojan_ws");
        let _enter = span.enter();
        let transport = transport::WsClient::new(
            "".to_owned(),
            10002,
            "/".to_owned(),
            [("Host".to_owned(), "example.org".to_owned())]
                .into_iter()
                .collect::<HashMap<_, _>>(),
            None,
            0,
            "".to_owned(),
        );
        let tls =
            transport::TlsClient::new(true, "example.org".to_owned(), None, None);

        let opts = HandlerOptions {
            name: "test-trojan-ws".to_owned(),
            common_opts: Default::default(),
            server: "127.0.0.1".to_owned(),
            port: 10002,
            password: "example".to_owned(),
            udp: true,
            tls: Some(Box::new(tls)),
            transport: Some(Box::new(transport)),
        };
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        // ignore the udp test
        run_test_suites_and_cleanup(handler, get_ws_runner().await?, Suite::all())
            .await
    }

    async fn get_grpc_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let conf = test_config_dir.join("trojan-grpc.json");
        let cert = test_config_dir.join("example.org.pem");
        let key = test_config_dir.join("example.org-key.pem");

        DockerTestRunnerBuilder::new()
            .image(IMAGE_XRAY)
            .mounts(&[
                (conf.to_str().unwrap(), "/etc/xray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_trojan_grpc() -> anyhow::Result<()> {
        let transport = transport::GrpcClient::new(
            "example.org".to_owned(),
            "example"
                .to_owned()
                .try_into()
                .expect("invalid grpc service name"),
        );
        let tls = transport::TlsClient::new(
            true,
            "example.org".to_owned(),
            Some(vec!["http/1.1".to_owned(), "h2".to_owned()]),
            None,
        );

        let opts = HandlerOptions {
            name: "test-trojan-grpc".to_owned(),
            common_opts: Default::default(),
            server: "127.0.0.1".to_owned(),
            port: 10002,
            password: "example".to_owned(),
            udp: true,
            tls: Some(Box::new(tls)),
            transport: Some(Box::new(transport)),
        };
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(handler, get_grpc_runner().await?, Suite::all())
            .await
    }
}
