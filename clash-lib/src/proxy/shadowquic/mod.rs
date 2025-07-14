use std::{io, net::SocketAddr, str::FromStr};

use async_trait::async_trait;
use compat::UdpSessionWrapper;
use shadowquic::{
    config,
    msgs::socks5::SocksAddr as SQAddr,
    shadowquic::{
        SQConn,
        outbound::{self as SQ, ShadowQuicClient},
    },
};
use tokio::sync::{OnceCell, RwLock};
use tokio_util::sync::PollSender;
mod compat;
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    session::{Session, SocksAddr},
};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    utils::new_udp_socket,
};
use crate::app::dispatcher::ChainedStream;
use std::fmt::Debug;

pub type HandlerOptions = config::ShadowQuicClientCfg;

pub struct Handler {
    name: String,
    opts: HandlerOptions,
    ep: OnceCell<ShadowQuicClient>, /* Must be created after session since server
                                     * addr needs to be resolved */
    conn: RwLock<Option<SQConn>>,
}
impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler").field("opts", &self.opts).finish()
    }
}
impl Handler {
    pub fn new(name: String, opts: HandlerOptions) -> Self {
        Self {
            name,
            opts,
            ep: Default::default(),
            conn: Default::default(),
        }
    }

    /// Resolve quic server DNS with clash DNS resolver
    pub async fn prepare_endpoint(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<&ShadowQuicClient> {
        self.ep
            .get_or_try_init(|| async {
                let addr = self.opts.addr.clone();
                let sock_addr = SocksAddr::from_str(&format!("{addr}:443"))
                    .or(SocksAddr::from_str(&addr))
                    .map_err(new_io_error)?;
                tracing::info!("resolving host:{:?}", sock_addr);
                let addr = match sock_addr {
                    SocksAddr::Domain(host, port) => {
                        let addr = resolver
                            .resolve(&host, false)
                            .await
                            .map_err(|x| {
                                io::Error::new(
                                    io::ErrorKind::AddrNotAvailable,
                                    format!(
                                        "failed to resolve shadowquic domain \
                                         name:{x:?}"
                                    ),
                                )
                            })?
                            .ok_or(io::ErrorKind::AddrNotAvailable)?;
                        SocketAddr::new(addr, port)
                    }
                    SocksAddr::Ip(socket_addr) => socket_addr,
                };
                let socket = new_udp_socket(
                    None,
                    sess.iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                    Some(addr),
                )
                .await?;

                let mut ep = ShadowQuicClient::new_with_socket(
                    self.opts.clone(),
                    socket.into_std()?,
                )
                .map_err(new_io_error)?;
                ep.config.addr = addr.to_string();
                Ok(ep) as io::Result<ShadowQuicClient>
            })
            .await
    }

    async fn prepare_conn(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<SQConn> {
        let ep = self.prepare_endpoint(sess, resolver).await?;
        if let Some(x) = &*self.conn.read().await
            && x.close_reason().is_none()
        {
            return Ok(x.clone());
        }
        let mut conn = self.conn.write().await;
        let newconn = ep.get_conn().await.map_err(|x| {
            io::Error::other(format!("can't open shadowquic connection due to:{x}"))
        })?;
        conn.replace(newconn.clone());
        Ok(newconn)
    }
}

#[async_trait]
impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    /// The name of the outbound handler
    fn name(&self) -> &str {
        &self.name
    }

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType {
        OutboundType::ShadowQuic
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        true
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let conn = self.prepare_conn(sess, resolver).await?;
        let conn =
            SQ::connect_tcp(&conn, to_sq_socks_addr(sess.destination.clone()))
                .await
                .map_err(|x| {
                    io::Error::other(format!(
                        "can't open shadowquic stream due to:{x}"
                    ))
                })?;
        let s = ChainedStreamWrapper::new(conn);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let conn = self.prepare_conn(sess, resolver).await?;
        // clash-rs didn't expose udp associate address, so set to unspecified
        // address
        let addr = if sess.source.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = SQ::associate_udp(
            &conn,
            addr.parse::<SocketAddr>().unwrap().into(),
            self.opts.over_stream,
        )
        .await
        .map_err(|x| {
            io::Error::other(format!("can't open shadowquic stream due to:{x}"))
        })?;
        let chain = ChainedDatagramWrapper::new(UdpSessionWrapper {
            s: PollSender::new(socket.0),
            r: socket.1,
            src_addr: sess.source.into(),
        });
        chain.append_to_chain(self.name()).await;
        Ok(Box::new(chain))
    }

    /// relay related
    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }
}

fn to_sq_socks_addr(x: SocksAddr) -> SQAddr {
    match x {
        SocksAddr::Ip(socket_addr) => SQAddr::from(socket_addr),
        SocksAddr::Domain(host, port) => SQAddr::from_domain(host, port),
    }
}
fn to_clash_socks_addr(x: SQAddr) -> SocksAddr {
    match x.addr {
        shadowquic::msgs::socks5::AddrOrDomain::V4(ip) => {
            SocksAddr::Ip(SocketAddr::new(ip.into(), x.port))
        }
        shadowquic::msgs::socks5::AddrOrDomain::V6(ip) => {
            SocksAddr::Ip(SocketAddr::new(ip.into(), x.port))
        }
        shadowquic::msgs::socks5::AddrOrDomain::Domain(domain) => {
            SocksAddr::Domain(String::from_utf8(domain.contents).unwrap(), x.port)
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
    use std::sync::Arc;

    use super::*;
    async fn get_shadowquic_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let conf = test_config_dir.join("shadowquic.yaml");

        DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOWQUIC)
            .mounts(&[(conf.to_str().unwrap(), "/etc/shadowquic/config.yaml")])
            .build()
            .await
    }

    const PORT: u16 = 10002;

    fn gen_options(over_stream: bool) -> anyhow::Result<HandlerOptions> {
        Ok(HandlerOptions {
            addr: SocketAddr::new(LOCAL_ADDR.parse().unwrap(), PORT).to_string(),
            password: "12345678".into(),
            username: "87654321".into(),
            server_name: "echo.free.beeceptor.com".into(),
            alpn: vec!["h3".into()],
            initial_mtu: 1400,
            zero_rtt: true,
            over_stream,
            ..Default::default()
        })
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_shadowquic_over_datagram() -> anyhow::Result<()> {
        initialize();
        let opts = gen_options(false)?;

        let handler = Arc::new(Handler::new("test-shadowquic".into(), opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(
            handler,
            get_shadowquic_runner().await?,
            Suite::all(),
        )
        .await
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn test_shadowquic_over_stream() -> anyhow::Result<()> {
        initialize();
        let mut opts = gen_options(true)?;
        opts.over_stream = true;

        let handler = Arc::new(Handler::new("test-shadowquic".into(), opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(
            handler,
            get_shadowquic_runner().await?,
            Suite::all(),
        )
        .await
    }
}
