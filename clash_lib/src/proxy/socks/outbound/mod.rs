mod datagram;

use std::{fmt::Debug, sync::Arc};

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
    proxy::{
        transport::{self, TLSOptions},
        utils::{new_udp_socket, RemoteConnector, GLOBAL_DIRECT_CONNECTOR},
        AnyStream, CommonOption, ConnectorType, DialWithConnector, OutboundHandler,
        OutboundType,
    },
    session::Session,
};

use async_trait::async_trait;
use datagram::Socks5Datagram;
use tracing::{debug, trace};

use super::socks5::{client_handshake, socks_command};

#[derive(Default)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: CommonOption,
    pub server: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub udp: bool,
    pub tls: bool,
    pub sni: String,
    pub skip_cert_verify: bool,
}

pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::Mutex<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5")
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

    async fn inner_connect_stream(
        &self,
        s: AnyStream,
        sess: &Session,
    ) -> std::io::Result<AnyStream> {
        let mut s = if self.opts.tls {
            trace!(
                "TLS config - enabled: {}, skip_cert_verify: {}, sni: {}",
                self.opts.tls,
                self.opts.skip_cert_verify,
                self.opts.sni
            );
            let tls_opt = TLSOptions {
                skip_cert_verify: self.opts.skip_cert_verify,
                sni: self.opts.sni.clone(),
                alpn: None,
            };

            transport::tls::wrap_stream(s, tls_opt, None).await?
        } else {
            s
        };

        client_handshake(
            &mut s,
            &sess.destination,
            socks_command::CONNECT,
            self.opts.user.clone(),
            self.opts.password.clone(),
        )
        .await?;

        Ok(s)
    }

    async fn inner_connect_datagram(
        &self,
        s: AnyStream,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<Socks5Datagram> {
        let mut s = if self.opts.tls {
            let tls_opt = TLSOptions {
                skip_cert_verify: self.opts.skip_cert_verify,
                sni: self.opts.sni.clone(),
                alpn: None,
            };

            transport::tls::wrap_stream(s, tls_opt, None).await?
        } else {
            s
        };

        let bind_addr = client_handshake(
            &mut s,
            &sess.destination,
            socks_command::UDP_ASSOCIATE,
            self.opts.user.clone(),
            self.opts.password.clone(),
        )
        .await?;

        let bind_ip = bind_addr
            .ip()
            .ok_or(new_io_error("missing IP in bind address"))?;
        let bind_ip = if bind_ip.is_unspecified() {
            trace!("bind address is unspecified, resolving server address");
            let remote_addr = resolver
                .resolve(&self.opts.server, false)
                .await
                .map_err(|x| new_io_error(x.to_string().as_str()))?;
            remote_addr.ok_or(new_io_error(
                "no bind addr returned from server and failed to resolve server \
                 address",
            ))?
        } else {
            trace!("using server returned bind addr {}", bind_ip);
            bind_ip
        };
        let bind_port = bind_addr.port();
        trace!("bind address resolved to {}:{}", bind_ip, bind_port);

        let udp_socket = new_udp_socket(
            None,
            self.opts.common_opts.iface.clone().or(sess.iface.clone()),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        )
        .await?;

        Ok(Socks5Datagram::new(
            s,
            (bind_ip, bind_port).into(),
            udp_socket,
        ))
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Socks5
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
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

    // it;s up to the server to allow full cone UDP
    // https://github.com/wzshiming/socks5/blob/0e66f80351778057703bd652e8b177fabe443f34/server.go#L368
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
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
    ) -> std::io::Result<BoxedChainedStream> {
        let s = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                self.opts.common_opts.iface.as_ref().or(sess.iface.as_ref()),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                None,
            )
            .await?;

        let s = self.inner_connect_stream(s, sess).await?;

        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let s = connector
            .connect_stream(
                resolver.clone(),
                self.opts.server.as_str(),
                self.opts.port,
                self.opts.common_opts.iface.as_ref().or(sess.iface.as_ref()),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                None,
            )
            .await?;

        let d = self.inner_connect_datagram(s, sess, resolver).await?;

        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }
}

#[cfg(all(test, not(ci)))]
mod tests {

    use std::sync::Arc;

    use crate::proxy::{
        socks::{Handler, HandlerOptions},
        utils::{
            test_utils::{
                consts::{IMAGE_SOCKS5, LOCAL_ADDR},
                docker_runner::{DockerTestRunner, DockerTestRunnerBuilder},
                run_test_suites_and_cleanup, Suite,
            },
            GLOBAL_DIRECT_CONNECTOR,
        },
    };

    const USER: &str = "user";
    const PASSWORD: &str = "password";

    async fn get_socks5_runner(
        port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> anyhow::Result<DockerTestRunner> {
        let host = format!("0.0.0.0:{}", port);
        let username = username.unwrap_or_default();
        let password = password.unwrap_or_default();
        let cmd = if username != "" && password != "" {
            vec![
                "-a",
                &host,
                "-u",
                username.as_str(),
                "-p",
                password.as_str(),
            ]
        } else {
            vec!["-a", &host]
        };
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SOCKS5)
            .cmd(&cmd)
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_socks5_no_auth() -> anyhow::Result<()> {
        let _ = tracing_subscriber::fmt().try_init();
        let opts = HandlerOptions {
            name: "test-socks5-no-auth".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: 10002,
            user: None,
            password: None,
            udp: true,
            ..Default::default()
        };
        let port = opts.port;
        let handler = Arc::new(Handler::new(opts));
        run_test_suites_and_cleanup(
            handler,
            get_socks5_runner(port, None, None).await?,
            Suite::all(),
        )
        .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_socks5_auth() -> anyhow::Result<()> {
        use crate::proxy::DialWithConnector;

        let _ = tracing_subscriber::fmt().try_init();
        let opts = HandlerOptions {
            name: "test-socks5-no-auth".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: 10002,
            user: Some(USER.to_owned()),
            password: Some(PASSWORD.to_owned()),
            udp: true,
            ..Default::default()
        };
        let port = opts.port;
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(
            handler,
            get_socks5_runner(
                port,
                Some(USER.to_owned()),
                Some(PASSWORD.to_owned()),
            )
            .await?,
            Suite::all(),
        )
        .await
    }
}
