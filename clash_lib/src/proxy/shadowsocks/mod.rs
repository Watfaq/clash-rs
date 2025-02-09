mod datagram;
mod shadow_tls;
mod simple_obfs;
mod stream;
mod v2ray;

use self::{datagram::OutboundDatagramShadowsocks, stream::ShadowSocksStream};
use super::{
    utils::{RemoteConnector, GLOBAL_DIRECT_CONNECTOR},
    AnyStream, ConnectorType, DialWithConnector, OutboundType,
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
    config::ServerType, context::Context, crypto::CipherKind,
    relay::udprelay::proxy_socket::UdpSocketType, ProxyClientStream, ProxySocket,
    ServerConfig,
};
use std::{collections::HashMap, fmt::Debug, io, sync::Arc};
use tracing::debug;

#[derive(Clone, Copy)]
pub enum SimpleOBFSMode {
    Http,
    Tls,
}

pub struct SimpleOBFSOption {
    pub mode: SimpleOBFSMode,
    pub host: String,
}

#[allow(dead_code)]
pub struct V2RayOBFSOption {
    pub mode: String,
    pub host: String,
    pub path: String,
    pub tls: bool,
    pub headers: HashMap<String, String>,
    pub skip_cert_verify: bool,
    pub mux: bool,
}

#[derive(Debug)]
pub struct ShadowTlsOption {
    pub host: String,
    pub password: String,
    pub strict: bool,
}

pub enum OBFSOption {
    Simple(SimpleOBFSOption),
    V2Ray(V2RayOBFSOption),
    ShadowTls(ShadowTlsOption),
}

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub plugin_opts: Option<OBFSOption>,
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
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        let stream: AnyStream = match &self.opts.plugin_opts {
            Some(plugin) => match plugin {
                OBFSOption::Simple(opts) => match opts.mode {
                    SimpleOBFSMode::Http => simple_obfs::SimpleObfsHTTP::new(
                        s,
                        opts.host.clone(),
                        self.opts.port,
                    )
                    .into(),
                    SimpleOBFSMode::Tls => {
                        simple_obfs::SimpleObfsTLS::new(s, opts.host.clone()).into()
                    }
                },
                OBFSOption::V2Ray(_opt) => {
                    todo!("v2ray-plugin is not implemented yet")
                }
                OBFSOption::ShadowTls(opts) => {
                    tracing::trace!("using shadow-tls");

                    (shadow_tls::Connector::wrap(opts, s).await?) as _
                }
            },
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
                    ))
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
                #[cfg(any(target_os = "linux", target_os = "android"))]
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
                #[cfg(any(target_os = "linux", target_os = "android"))]
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
            .resolve(&self.opts.server, false)
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
        proxy::utils::test_utils::{
            docker_runner::{DockerTestRunnerBuilder, MultiDockerTestRunner},
            run_test_suites_and_cleanup, Suite,
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
            plugin_opts: Default::default(),
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
        let opts = HandlerOptions {
            name: "test-shadowtls".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: shadow_tls_port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin_opts: Some(OBFSOption::ShadowTls(ShadowTlsOption {
                host: "www.feishu.cn".to_owned(),
                password: "password".to_owned(),
                strict: true,
            })),
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
        let opts = HandlerOptions {
            name: "test-obfs".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: obfs_port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin_opts: Some(OBFSOption::Simple(SimpleOBFSOption {
                host: "www.bing.com".to_owned(),
                mode,
            })),
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
}
