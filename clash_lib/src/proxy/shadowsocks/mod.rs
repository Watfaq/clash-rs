mod datagram;
mod shadow_tls;
mod simple_obfs;
mod stream;
mod v2ray;

use async_trait::async_trait;
use futures::TryFutureExt;
use shadowsocks::{
    config::ServerType, context::Context, crypto::CipherKind,
    relay::udprelay::proxy_socket::UdpSocketType, ProxyClientStream, ProxySocket, ServerConfig,
};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram, ChainedDatagramWrapper,
            ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    proxy::{CommonOption, OutboundHandler},
    session::{Session, SocksAddr},
    Error,
};
use std::{collections::HashMap, io, sync::Arc};

use self::{datagram::OutboundDatagramShadowsocks, stream::ShadowSocksStream};

use super::{
    utils::{new_tcp_stream, new_udp_socket},
    AnyOutboundHandler, AnyStream, OutboundType,
};

pub enum SimpleOBFSMode {
    Http,
    Tls,
}

pub struct SimpleOBFSOption {
    pub mode: SimpleOBFSMode,
    pub host: String,
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for SimpleOBFSOption {
    type Error = crate::Error;

    fn try_from(value: HashMap<String, serde_yaml::Value>) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

        match mode {
            "http" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Http,
                host: host.to_owned(),
            }),
            "tls" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Tls,
                host: host.to_owned(),
            }),
            _ => Err(Error::InvalidConfig(format!("invalid obfs mode: {}", mode))),
        }
    }
}

pub struct V2RayOBFSOption {
    pub mode: String,
    pub host: String,
    pub path: String,
    pub tls: bool,
    pub headers: HashMap<String, String>,
    pub skip_cert_verify: bool,
    pub mux: bool,
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for V2RayOBFSOption {
    type Error = crate::Error;

    fn try_from(value: HashMap<String, serde_yaml::Value>) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

        if mode != "websocket" {
            return Err(Error::InvalidConfig(format!("invalid obfs mode: {}", mode)));
        }

        let path = value
            .get("path")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs path is required".to_owned()))?;
        let mux = value.get("mux").and_then(|x| x.as_bool()).unwrap_or(false);
        let tls = value.get("tls").and_then(|x| x.as_bool()).unwrap_or(false);
        let skip_cert_verify = value
            .get("skip-cert-verify")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);

        let mut headers = HashMap::new();
        if let Some(h) = value.get("headers") {
            if let Some(h) = h.as_mapping() {
                for (k, v) in h {
                    if let (Some(k), Some(v)) = (k.as_str(), v.as_str()) {
                        headers.insert(k.to_owned(), v.to_owned());
                    }
                }
            }
        }

        Ok(V2RayOBFSOption {
            mode: mode.to_owned(),
            host: host.to_owned(),
            path: path.to_owned(),
            tls,
            headers,
            skip_cert_verify,
            mux,
        })
    }
}

#[derive(Debug)]
pub struct ShadowTlsOption {
    pub host: String,
    pub password: String,
    pub strict: bool,
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for ShadowTlsOption {
    type Error = crate::Error;

    fn try_from(value: HashMap<String, serde_yaml::Value>) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let password = value
            .get("password")
            .and_then(|x| x.as_str().to_owned())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;
        let strict = value
            .get("strict")
            .and_then(|x| x.as_bool())
            .unwrap_or(true);

        Ok(Self {
            host: host.to_string(),
            password: password.to_string(),
            strict,
        })
    }
}

pub enum OBFSOption {
    Simple(SimpleOBFSOption),
    V2Ray(V2RayOBFSOption),
    ShadowTls(ShadowTlsOption),
}

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: CommonOption,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub plugin_opts: Option<OBFSOption>,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
}

impl Handler {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(opts: HandlerOptions) -> AnyOutboundHandler {
        Arc::new(Self { opts })
    }

    async fn proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        let stream: AnyStream = match &self.opts.plugin_opts {
            Some(plugin) => match plugin {
                OBFSOption::Simple(opts) => {
                    tracing::warn!("simple-obfs is deprecated, please use v2ray-plugin instead");
                    match opts.mode {
                        SimpleOBFSMode::Http => {
                            simple_obfs::SimpleObfsHTTP::new(s, opts.host.clone(), self.opts.port)
                                .into()
                        }
                        SimpleOBFSMode::Tls => {
                            simple_obfs::SimpleObfsTLS::new(s, opts.host.clone()).into()
                        }
                    }
                }
                OBFSOption::V2Ray(_opt) => {
                    todo!("v2ray-plugin is not implemented yet")
                }
                OBFSOption::ShadowTls(opts) => {
                    tracing::debug!("using shadow-tls with option: {:?}", opts);

                    (shadow_tls::Connector::wrap(opts, s).await?) as _
                }
            },
            None => s,
        };

        let ctx = Context::new_shared(ServerType::Local);
        let cfg = ServerConfig::new(
            (self.opts.server.to_owned(), self.opts.port),
            self.opts.password.to_owned(),
            match self.opts.cipher.as_str() {
                "aes-128-gcm" => CipherKind::AES_128_GCM,
                "aes-256-gcm" => CipherKind::AES_256_GCM,
                "chacha20-ietf-poly1305" => CipherKind::CHACHA20_POLY1305,
                _ => return Err(io::Error::new(io::ErrorKind::Other, "unsupported cipher")),
            },
        );

        let stream = ProxyClientStream::from_stream(
            ctx,
            stream,
            &cfg,
            (sess.destination.host(), sess.destination.port()),
        );

        Ok(Box::new(ShadowSocksStream(stream)))
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

    async fn remote_addr(&self) -> Option<SocksAddr> {
        Some(SocksAddr::Domain(self.opts.server.clone(), self.opts.port))
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let stream = new_tcp_stream(
            resolver.clone(),
            self.opts.server.as_str(),
            self.opts.port,
            self.opts.common_opts.iface.as_ref(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        )
        .map_err(|x| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "dial outbound {}:{}: {}",
                    self.opts.server, self.opts.port, x
                ),
            )
        })
        .await?;

        let s = self.proxy_stream(stream, sess, resolver).await?;
        let chained = ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram(
        &self,
        #[allow(unused_variables)] sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let ctx = Context::new_shared(ServerType::Local);
        let cfg = ServerConfig::new(
            (self.opts.server.to_owned(), self.opts.port),
            self.opts.password.to_owned(),
            match self.opts.cipher.as_str() {
                "aes-128-gcm" => CipherKind::AES_128_GCM,
                "aes-256-gcm" => CipherKind::AES_256_GCM,
                "chacha20-ietf-poly1305" => CipherKind::CHACHA20_POLY1305,
                _ => return Err(io::Error::new(io::ErrorKind::Other, "unsupported cipher")),
            },
        );
        let socket = new_udp_socket(
            None,
            self.opts.common_opts.iface.as_ref(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        )
        .await?;
        let socket = ProxySocket::from_socket(UdpSocketType::Client, ctx, &cfg, socket);
        let d = OutboundDatagramShadowsocks::new(
            socket,
            (self.opts.server.to_owned(), self.opts.port),
            resolver,
        );
        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }
}

#[cfg(all(test, not(ci)))]
mod tests {

    use super::super::utils::test_utils::{consts::*, docker_runner::DockerTestRunner};
    use crate::proxy::utils::test_utils::{
        docker_runner::{DockerTestRunnerBuilder, MultiDockerTestRunner},
        run_default_test_suites_and_cleanup,
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
            .cmd(&["-s", &host, "-m", CIPHER, "-k", PASSWORD, "-U"])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_ss() -> anyhow::Result<()> {
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
        let handler = Handler::new(opts);
        run_default_test_suites_and_cleanup(handler, get_ss_runner(port).await?).await
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
        // not important, you can assign any port that is not conflict with others
        let ss_port = 10004;
        let opts = HandlerOptions {
            name: "test-ss".to_owned(),
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
        let handler = Handler::new(opts);
        // we need to store all the runners in a container, to make sure all of them can be destroyed after the test
        let mut chained = MultiDockerTestRunner::default();
        chained.add(get_ss_runner(ss_port)).await;
        chained
            .add(get_shadowtls_runner(ss_port, shadow_tls_port))
            .await;
        run_default_test_suites_and_cleanup(handler, chained).await
    }
}
