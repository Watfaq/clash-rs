mod datagram;
mod stream;

use self::{datagram::OutboundDatagramShadowsocks, stream::ShadowSocksStream};
use super::{
    AnyStream, ConnectorType, DialWithConnector, OutboundType,
    transport::Sip003Plugin,
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
    proxy::{HandlerCommonOptions, OutboundHandler},
    session::Session,
};
use async_trait::async_trait;
use datagram::ShadowsocksUdpIo;
use shadowsocks::{
    ProxyClientStream, ProxySocket, ServerConfig, config::ServerType,
    context::Context, crypto::CipherKind,
    relay::udprelay::proxy_socket::UdpSocketType,
};
use std::{fmt::Debug, io, sync::Arc};
use tracing::debug;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub plugin: Option<Box<dyn Sip003Plugin>>,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::Mutex<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shadowsocks")
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

    async fn proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        let stream: AnyStream = match &self.opts.plugin {
            Some(plugin) => plugin.proxy_stream(s).await?,
            None => s,
        };

        let ctx = Context::new_shared(ServerType::Local);
        let cfg = self.server_config()?;

        let stream = ProxyClientStream::from_stream(
            ctx,
            stream,
            &cfg,
            (sess.destination.host(), sess.destination.port()),
        );

        Ok(Box::new(ShadowSocksStream(stream)))
    }

    fn server_config(&self) -> Result<ServerConfig, io::Error> {
        ServerConfig::new(
            (self.opts.server.to_owned(), self.opts.port),
            self.opts.password.to_owned(),
            match self.opts.cipher.as_str() {
                "aes-128-gcm" => CipherKind::AES_128_GCM,
                "aes-256-gcm" => CipherKind::AES_256_GCM,
                "chacha20-ietf-poly1305" => CipherKind::CHACHA20_POLY1305,

                "2022-blake3-aes-128-gcm" => CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
                "2022-blake3-aes-256-gcm" => CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
                "2022-blake3-chacha20-ietf-poly1305" => {
                    CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305
                }

                "rc4-md5" => CipherKind::SS_RC4_MD5,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "unsupported cipher",
                    ));
                }
            },
        )
        .map_err(|e| new_io_error(e.to_string()))
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        self.opts.name.as_str()
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Shadowsocks
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
                resolver.clone(),
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let s = self.proxy_stream(stream, sess, resolver).await?;
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
        let ctx = Context::new_shared(ServerType::Local);
        let cfg = self.server_config()?;

        let socket = connector
            .connect_datagram(
                resolver.clone(),
                None,
                (self.opts.server.clone(), self.opts.port).try_into()?,
                sess.iface.as_ref().cloned(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let socket = ProxySocket::from_socket(
            UdpSocketType::Client,
            ctx,
            &cfg,
            ShadowsocksUdpIo::new(socket),
        );
        let server_addr = resolver
            .resolve_old(&self.opts.server, false)
            .await
            .map_err(|x| {
                new_io_error(format!(
                    "failed to resolve {}: {}",
                    self.opts.server, x
                ))
            })?
            .ok_or(new_io_error(format!(
                "failed to resolve {}",
                self.opts.server
            )))?;
        let d = OutboundDatagramShadowsocks::new(
            socket,
            (server_addr, self.opts.port).into(),
        );
        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use super::super::utils::test_utils::{
        consts::*, docker_runner::DockerTestRunner,
    };
    use crate::{
        proxy::{
            transport::*,
            utils::test_utils::{
                Suite,
                config_helper::test_config_base_dir,
                docker_runner::{DockerTestRunnerBuilder, MultiDockerTestRunner},
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    use super::*;

    const PASSWORD: &str = "FzcLbKs2dY9mhL";
    const CIPHER: &str = "aes-256-gcm";
    const SHADOW_TLS_PASSWORD: &str = "password";

    async fn get_ss_runner(port: u16) -> anyhow::Result<DockerTestRunner> {
        let host = format!("0.0.0.0:{}", port);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SS_RUST)
            .entrypoint(&["ssserver"])
            .cmd(&["-s", &host, "-m", CIPHER, "-k", PASSWORD, "-U", "-vvv"])
            .build()
            .await
    }

    async fn get_ss_runner_with_plugin(
        port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("example.org.pem");
        let key = test_config_dir.join("example.org-key.pem");
        let host = format!("0.0.0.0:{}", port);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SS_RUST)
            .entrypoint(&["ssserver"])
            .cmd(&[
                "-s",
                &host,
                "-m",
                CIPHER,
                "-k",
                PASSWORD,
                "-U",
                "-vvv",
                "--plugin",
                "v2ray-plugin",
                "--plugin-opts",
                "server;tls;host=example.org;mux=0",
            ])
            .mounts(&[
                (
                    cert.to_str().unwrap(),
                    "/root/.acme.sh/example.org/fullchain.cer",
                ),
                (
                    key.to_str().unwrap(),
                    "/root/.acme.sh/example.org/example.org.key",
                ),
            ])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_ss_plain() -> anyhow::Result<()> {
        initialize();
        let opts = HandlerOptions {
            name: "test-ss".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: 10002,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Default::default(),
            udp: false,
        };
        let port = opts.port;
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(
            handler,
            get_ss_runner(port).await?,
            Suite::all(),
        )
        .await
    }

    async fn get_shadowtls_runner(
        ss_port: u16,
        stls_port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        let ss_server_env = format!("SERVER=127.0.0.1:{}", ss_port);
        let listen_env = format!("LISTEN=0.0.0.0:{}", stls_port);
        let password = format!("PASSWORD={}", SHADOW_TLS_PASSWORD);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOW_TLS)
            .env(&[
                "MODE=server",
                // the port that we need to fill in the config
                &listen_env,
                // shadowsocks server addr
                &ss_server_env,
                "TLS=www.feishu.cn:443",
                &password,
                "V3=1",
            ])
            // .cmd(&["-s", "0.0.0.0:10002", "-m", CIPHER, "-k", PASSWORD, "-U"])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_shadowtls() -> anyhow::Result<()> {
        // the real port that used for communication
        let shadow_tls_port = 10002;
        // not important, you can assign any port that is not conflict with
        // others
        let ss_port = 10004;
        let client =
            Shadowtls::new("www.feishu.cn".to_owned(), "password".to_owned(), true);
        let opts = HandlerOptions {
            name: "test-shadowtls".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: shadow_tls_port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Some(Box::new(client)),
            udp: false,
        };
        let handler: Arc<dyn OutboundHandler> = Arc::new(Handler::new(opts));
        // we need to store all the runners in a container, to make sure all of
        // them can be destroyed after the test
        let mut chained = MultiDockerTestRunner::default();
        chained.add(get_ss_runner(ss_port)).await?;
        chained
            .add(get_shadowtls_runner(ss_port, shadow_tls_port))
            .await?;
        // currently, shadow-tls does't support udp proxy
        // see: https://github.com/ihciah/shadow-tls/issues/54
        run_test_suites_and_cleanup(handler, chained, Suite::tcp_tests()).await
    }

    async fn get_obfs_runner(
        ss_port: u16,
        obfs_port: u16,
        mode: SimpleOBFSMode,
    ) -> anyhow::Result<DockerTestRunner> {
        let ss_server_env = format!("127.0.0.1:{}", ss_port);
        let port = format!("{}", obfs_port);
        let mode = match mode {
            SimpleOBFSMode::Http => "http",
            SimpleOBFSMode::Tls => "tls",
        };
        DockerTestRunnerBuilder::new()
            .image(IMAGE_OBFS)
            .cmd(&[
                "obfs-server",
                "-p",
                &port,
                "--obfs",
                mode,
                "-r",
                &ss_server_env,
                "-vv",
            ])
            .build()
            .await
    }

    async fn test_ss_obfs_inner(mode: SimpleOBFSMode) -> anyhow::Result<()> {
        let obfs_port = 10002;
        let ss_port = 10004;
        let host = "www.bing.com".to_owned();
        let plugin = match mode {
            SimpleOBFSMode::Http => {
                Box::new(SimpleObfsHttp::new(host, ss_port)) as _
            }
            SimpleOBFSMode::Tls => Box::new(SimpleObfsTLS::new(host)) as _,
        };
        let opts = HandlerOptions {
            name: "test-obfs".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: obfs_port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Some(plugin),
            udp: false,
        };

        let handler: Arc<dyn OutboundHandler> = Arc::new(Handler::new(opts));
        let mut chained = MultiDockerTestRunner::default();
        chained.add(get_ss_runner(ss_port)).await?;
        chained
            .add(get_obfs_runner(ss_port, obfs_port, mode))
            .await?;
        run_test_suites_and_cleanup(handler, chained, Suite::tcp_tests()).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_ss_obfs_http() -> anyhow::Result<()> {
        test_ss_obfs_inner(SimpleOBFSMode::Http).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_ss_obfs_tls() -> anyhow::Result<()> {
        initialize();
        test_ss_obfs_inner(SimpleOBFSMode::Tls).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_ss_v2ray_plugin() -> anyhow::Result<()> {
        initialize();
        let ss_port = 10004;
        let host = "example.org".to_owned();
        let plugin = V2rayWsClient::try_new(
            host,
            ss_port,
            "/".to_owned(),
            Default::default(),
            true,
            true,
            false,
        )?;
        let opts = HandlerOptions {
            name: "test-obfs".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: ss_port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Some(Box::new(plugin)),
            udp: false,
        };

        let handler: Arc<dyn OutboundHandler> = Arc::new(Handler::new(opts));
        run_test_suites_and_cleanup(
            handler,
            get_ss_runner_with_plugin(ss_port).await?,
            Suite::tcp_tests(),
        )
        .await
    }
}
