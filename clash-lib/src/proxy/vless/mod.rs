use self::stream::VlessStream;
use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType,
    transport::Transport,
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
    impl_default_connector,
    proxy::vless::datagram::OutboundDatagramVless,
    session::Session,
};
use async_trait::async_trait;
use std::{io, sync::Arc};
use tracing::debug;

mod datagram;
mod stream;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub udp: bool,
    pub transport: Option<Box<dyn Transport>>,
    pub tls: Option<Box<dyn Transport>>,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vless")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
        }
    }

    async fn inner_proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        is_udp: bool,
    ) -> io::Result<AnyStream> {
        let s = if let Some(tls) = self.opts.tls.as_ref() {
            tls.proxy_stream(s).await?
        } else {
            s
        };

        let s = if let Some(transport) = self.opts.transport.as_ref() {
            transport.proxy_stream(s).await?
        } else {
            s
        };

        let vless_stream =
            VlessStream::new(s, &self.opts.uuid, &sess.destination, is_udp)?;

        Ok(Box::new(vless_stream))
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Vless
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
        let stream = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let s = self.inner_proxy_stream(stream, sess, false).await?;
        let chained = ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        let stream = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let stream = self.inner_proxy_stream(stream, sess, true).await?;
        let d = OutboundDatagramVless::new(stream, sess.destination.clone());

        let chained = ChainedDatagramWrapper::new(d);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}

#[cfg(all(test, docker_test))]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{
        proxy::{
            transport::{TlsClient, WsClient},
            utils::test_utils::{
                Suite,
                docker_utils::{
                    config_helper::test_config_base_dir,
                    consts::*,
                    docker_runner::{DockerTestRunner, DockerTestRunnerBuilder},
                },
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    fn tls_client(alpn: Option<Vec<String>>) -> Option<Box<dyn Transport>> {
        Some(Box::new(TlsClient::new(
            true,
            "example.org".to_owned(),
            alpn,
            None,
        )))
    }

    async fn get_ws_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let conf = test_config_dir.join("vless-ws-tls.json");
        let cert = test_config_dir.join("example.org.pem");
        let key = test_config_dir.join("example.org-key.pem");

        DockerTestRunnerBuilder::new()
            .image(IMAGE_VLESS)
            .mounts(&[
                (conf.to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_vless_ws() -> anyhow::Result<()> {
        initialize();
        let span = tracing::info_span!("test_vless_ws");
        let _enter = span.enter();
        let ws_client = WsClient::new(
            "".to_owned(),
            8443,
            "/websocket".to_owned(),
            [("Host".to_owned(), "example.org".to_owned())]
                .into_iter()
                .collect::<HashMap<_, _>>(),
            None,
            0,
            "".to_owned(),
        );

        let opts = HandlerOptions {
            name: "test-vless-ws".into(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.into(),
            port: 8443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            udp: true,
            tls: tls_client(None),
            transport: Some(Box::new(ws_client)),
        };
        let handler = Arc::new(Handler::new(opts));
        let runner = get_ws_runner().await?;
        run_test_suites_and_cleanup(handler, runner, Suite::all()).await
    }
}
