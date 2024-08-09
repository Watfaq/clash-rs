use std::{io, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tracing::debug;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::utils,
    impl_default_connector,
    session::Session,
};

use self::datagram::OutboundDatagramTrojan;

use super::{
    options::{GrpcOption, WsOption},
    transport::{self, TLSOptions},
    utils::{RemoteConnector, GLOBAL_DIRECT_CONNECTOR}, AnyStream, CommonOption, ConnectorType, DialWithConnector,
    OutboundHandler, OutboundType,
};

mod datagram;

static DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

pub enum Transport {
    Ws(WsOption),
    Grpc(GrpcOption),
}

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: CommonOption,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub udp: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: bool,
    pub transport: Option<Transport>,
}

pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::Mutex<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

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
        let tls_opt = TLSOptions {
            skip_cert_verify: self.opts.skip_cert_verify,
            sni: self.opts.sni.clone(),
            alpn: self.opts.alpn.clone().or(Some(
                DEFAULT_ALPN
                    .iter()
                    .copied()
                    .map(|x| x.to_owned())
                    .collect::<Vec<String>>(),
            )),
        };

        let s = transport::tls::wrap_stream(s, tls_opt, None).await?;

        let mut s = if let Some(transport) = self.opts.transport.as_ref() {
            match transport {
                Transport::Ws(ws_opts) => {
                    let ws_builder = transport::WebsocketStreamBuilder::new(
                        self.opts.server.clone(),
                        self.opts.port,
                        ws_opts.path.clone(),
                        ws_opts.headers.clone(),
                        None,
                        ws_opts.max_early_data,
                        ws_opts.early_data_header_name.clone(),
                    );

                    ws_builder.proxy_stream(s).await?
                }
                Transport::Grpc(grpc_opts) => {
                    let grpc_builder = transport::GrpcStreamBuilder::new(
                        grpc_opts.host.clone(),
                        grpc_opts
                            .service_name
                            .to_owned()
                            .try_into()
                            .expect("invalid gRPC service path"),
                    );
                    grpc_builder.proxy_stream(s).await?
                }
            }
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
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Trojan
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let dialer = self.connector.lock().await;

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
        let dialer = self.connector.lock().await;

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
                self.opts.common_opts.iface.as_ref().or(sess.iface.as_ref()),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                None,
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
                self.opts.common_opts.iface.as_ref().or(sess.iface.as_ref()),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                None,
            )
            .await?;

        let stream = self.inner_proxy_stream(stream, sess, true).await?;

        let d = OutboundDatagramTrojan::new(stream, sess.destination.clone());

        let chained = ChainedDatagramWrapper::new(d);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}

#[cfg(all(test, not(ci)))]
mod tests {

    use std::collections::HashMap;

    use crate::proxy::utils::test_utils::{
        config_helper::test_config_base_dir,
        consts::*,
        docker_runner::{DockerTestRunner, DockerTestRunnerBuilder},
        run_test_suites_and_cleanup, Suite,
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
        let _ = tracing_subscriber::fmt()
            // any additional configuration of the subscriber you might want here..
            .try_init();

        let span = tracing::info_span!("test_trojan_ws");
        let _enter = span.enter();

        let opts = HandlerOptions {
            name: "test-trojan-ws".to_owned(),
            common_opts: Default::default(),
            server: "127.0.0.1".to_owned(),
            port: 10002,
            password: "example".to_owned(),
            udp: true,
            sni: "example.org".to_owned(),
            alpn: None,
            skip_cert_verify: true,
            transport: Some(Transport::Ws(WsOption {
                path: "".to_owned(),
                headers: [("Host".to_owned(), "example.org".to_owned())]
                    .into_iter()
                    .collect::<HashMap<_, _>>(),
                // ignore the rest by setting max_early_data to 0
                max_early_data: 0,
                early_data_header_name: "".to_owned(),
            })),
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
        let opts = HandlerOptions {
            name: "test-trojan-grpc".to_owned(),
            common_opts: Default::default(),
            server: "127.0.0.1".to_owned(),
            port: 10002,
            password: "example".to_owned(),
            udp: true,
            sni: "example.org".to_owned(),
            alpn: None,
            skip_cert_verify: true,
            transport: Some(Transport::Grpc(GrpcOption {
                host: "example.org".to_owned(),
                service_name: "example".to_owned(),
            })),
        };
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(handler, get_grpc_runner().await?, Suite::all())
            .await
    }
}
