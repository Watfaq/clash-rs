use std::{
    fmt::{Debug, Formatter},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    path::PathBuf,
    pin::Pin,
    str::FromStr,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};
mod codec;
mod congestion;
mod salamander;
mod udp_hop;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, TokioRuntime,
};
use quinn_proto::TransportConfig;

use rustls::{self, ClientConfig as RustlsClientConfig};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::{errors::new_io_error, tls::DefaultTlsVerifier},
    // proxy::hysteria2::congestion::DynCongestion,
    session::{Session, SocksAddr},
};
use tracing::{debug, trace, warn};

use self::{
    codec::Hy2TcpCodec,
    congestion::{Burtal, DynController},
};

use super::{
    converters::hysteria2::PortGenerator, utils::new_udp_socket, ConnectorType,
    DialWithConnector, OutboundHandler, OutboundType,
};

#[derive(Clone)]
pub struct SalamanderObfs {
    pub key: Vec<u8>,
}

#[derive(Clone)]
pub enum Obfs {
    Salamander(SalamanderObfs),
}

#[derive(Clone)]
pub struct HystOption {
    pub name: String,
    pub addr: SocksAddr,
    pub ports: Option<PortGenerator>,
    pub sni: Option<String>,
    pub passwd: String,
    pub obfs: Option<Obfs>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    #[allow(dead_code)]
    pub up_down: Option<(u64, u64)>,
    pub fingerprint: Option<String>,
    pub ca: Option<PathBuf>,
    #[allow(dead_code)]
    pub ca_str: Option<String>,
    #[allow(dead_code)]
    pub cwnd: Option<u64>,
}

enum CcRx {
    Auto,
    Fixed(#[allow(dead_code)] u64),
}

impl FromStr for CcRx {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("auto") {
            Ok(Self::Auto)
        } else {
            let n = s.parse::<u64>()?;
            Ok(Self::Fixed(n))
        }
    }
}

pub struct Handler {
    opts: HystOption,
    ep_config: quinn::EndpointConfig,
    client_config: quinn::ClientConfig,
    session: Mutex<Option<Arc<quinn::Connection>>>,
    // a send request guard to keep the connection alive
    guard: Mutex<Option<SendRequest<OpenStreams, Bytes>>>,
    // support udp is decided by server
    support_udp: RwLock<bool>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystClient").finish()
    }
}

impl Handler {
    const DEFAULT_MAX_IDLE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(300);

    pub fn new(opts: HystOption) -> anyhow::Result<Self> {
        if opts.ca.is_some() {
            warn!("hysteria2 does not support ca yet");
        }
        let verify =
            DefaultTlsVerifier::new(opts.fingerprint.clone(), opts.skip_cert_verify);
        let mut tls_config = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verify))
            .with_no_client_auth();

        // should set alpn_protocol `h3` default
        tls_config.alpn_protocols = if opts.alpn.is_empty() {
            vec![b"h3".to_vec()]
        } else {
            opts.alpn.iter().map(|x| x.as_bytes().to_vec()).collect()
        };

        let mut transport = TransportConfig::default();
        // TODO
        // transport.congestion_controller_factory(DynCongestion);
        transport.max_idle_timeout(Some(
            Self::DEFAULT_MAX_IDLE_TIMEOUT.try_into().unwrap(),
        ));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

        let quic_config: QuicClientConfig = tls_config.try_into().unwrap();
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));
        let ep_config = quinn::EndpointConfig::default();

        Ok(Self {
            opts,
            ep_config,
            client_config,
            session: Mutex::new(None),
            guard: Mutex::new(None),
            support_udp: RwLock::new(true),
        })
    }

    async fn new_authed_session(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> anyhow::Result<(Connection, SendRequest<OpenStreams, Bytes>)> {
        // Everytime we enstablish a new session, we should lookup the server
        // address. maybe it changed since it use ddns
        let server_socket_addr = match self.opts.addr.clone() {
            SocksAddr::Ip(ip) => ip,
            SocksAddr::Domain(d, port) => {
                let ip = resolver
                    .resolve(d.as_str(), true)
                    .await?
                    .ok_or_else(|| anyhow!("resolve domain {} failed", d))?;
                SocketAddr::new(ip, port)
            }
        };

        let src = if resolver.ipv6() {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        };

        // Here maybe we should use a AsyncUdpSocket which implement salamander obfs
        // and port hopping
        let create_socket = || async {
            new_udp_socket(
                Some(src),
                sess.iface.clone(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await
        };

        let mut ep = if let Some(obfs) = self.opts.obfs.as_ref() {
            match obfs {
                Obfs::Salamander(salamander_obfs) => {
                    let socket = create_socket().await?;
                    let obfs = salamander::Salamander::new(
                        socket.into_std()?,
                        salamander_obfs.key.to_vec(),
                    )?;

                    quinn::Endpoint::new_with_abstract_socket(
                        self.ep_config.clone(),
                        None,
                        Arc::new(obfs),
                        Arc::new(TokioRuntime),
                    )?
                }
            }
        } else if let Some(port_gen) = self.opts.ports.as_ref() {
            let udp_hop = udp_hop::UdpHop::new(
                server_socket_addr.port(),
                port_gen.clone(),
                None,
            )?;
            quinn::Endpoint::new_with_abstract_socket(
                self.ep_config.clone(),
                None,
                Arc::new(udp_hop),
                Arc::new(TokioRuntime),
            )?
        } else {
            let socket = create_socket().await?;

            quinn::Endpoint::new(
                self.ep_config.clone(),
                None,
                socket.into_std()?,
                Arc::new(TokioRuntime),
            )?
        };

        ep.set_default_client_config(self.client_config.clone());

        let session = ep
            .connect(server_socket_addr, self.opts.sni.as_deref().unwrap_or(""))?
            .await?;
        let (guard, _rx, udp) = Self::auth(&session, &self.opts.passwd).await?;
        *self.support_udp.write().unwrap() = udp;
        // todo set congestion controller according to cc_rx

        match session
            .congestion_state()
            .into_any()
            .downcast::<DynController>()
        {
            Ok(any) => {
                any.set_controller(Box::new(Burtal::new(0, session.clone())));
            }
            Err(_) => {
                trace!("congestion controller is not set");
            }
        }

        Ok((session, guard))
    }

    async fn auth(
        conn: &quinn::Connection,
        passwd: &str,
    ) -> anyhow::Result<(SendRequest<OpenStreams, Bytes>, CcRx, bool)> {
        let h3_conn = h3_quinn::Connection::new(conn.clone());

        let (_, mut sender) =
            h3::client::builder().build::<_, _, Bytes>(h3_conn).await?;

        let req = http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", passwd)
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", codec::padding(64..=512))
            .body(())
            .unwrap();
        let mut r = sender.send_request(req).await?;
        r.finish().await?;

        let r = r.recv_response().await?;

        const HYSTERIA_STATUS_OK: u16 = 233;
        if r.status() != HYSTERIA_STATUS_OK {
            return Err(anyhow!("auth failed: response status code {}", r.status()));
        }

        // MUST have Hysteria-CC-RX and Hysteria-UDP headers according to hysteria2
        // document
        let cc_rx = r
            .headers()
            .get("Hysteria-CC-RX")
            .ok_or_else(|| anyhow!("auth failed: missing Hysteria-CC-RX header"))?
            .to_str()?
            .parse()?;

        let support_udp = r
            .headers()
            .get("Hysteria-UDP")
            .ok_or_else(|| anyhow!("auth failed: missing Hysteria-UDP header"))?
            .to_str()?
            .parse()?;

        Ok((sender, cc_rx, support_udp))
    }
}

impl DialWithConnector for Handler {}

#[async_trait::async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Hysteria2
    }

    async fn support_udp(&self) -> bool {
        *self.support_udp.read().unwrap()
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        Err(new_io_error("hysteria2 udp is not implemented yet"))
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let authed_conn = {
            let mut session_lock = self.session.lock().await;

            match (*session_lock).as_ref().filter(|s| match s.close_reason() {
                // rust should have inspect method on Option and Result!
                Some(reason) => {
                    tracing::debug!("old connection closed: {:?}", reason);
                    false
                }
                None => true,
            }) {
                Some(s) => s.clone(),
                None => {
                    let (session, guard) = self
                        .new_authed_session(sess, resolver)
                        .await
                        .map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!(
                                    "connect to {} failed: {}",
                                    self.opts.addr, e
                                ),
                            )
                        })?;
                    let session = Arc::new(session);
                    *session_lock = Some(session.clone());
                    *self.guard.lock().await = Some(guard);
                    session
                }
            }
        };

        let (mut tx, mut rx) = authed_conn.open_bi().await?;

        tokio_util::codec::FramedWrite::new(&mut tx, Hy2TcpCodec)
            .send(&sess.destination)
            .await?;

        match tokio_util::codec::FramedRead::new(&mut rx, Hy2TcpCodec)
            .next()
            .await
        {
            Some(Ok(resp)) => {
                if resp.status != 0x00 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "server response error: addr: {}, msg: {:?}",
                            self.opts.addr, resp.msg
                        ),
                    ));
                } else {
                    debug!(
                        "hysteria2 tcp request success: status: {}, msg: {:?}",
                        resp.status, resp.msg
                    );
                }
            }
            _ => {
                return Err(std::io::Error::other(format!(
                    "not receive hysteria2 response from server: {}",
                    self.opts.addr
                )));
            }
        };

        let hyster_client = HystStream { send: tx, recv: rx };
        Ok(Box::new(ChainedStreamWrapper::new(Box::new(hyster_client))))
    }
}

pub struct HystStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Debug for HystStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystStream").finish()
    }
}

impl AsyncRead for HystStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for HystStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map_err(|e| {
                tracing::error!("hysteria2 write error: {}", e);
                e.into()
            })
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use std::net::IpAddr;

    use super::super::utils::test_utils::{
        consts::*, docker_runner::DockerTestRunner,
    };
    use crate::{
        proxy::utils::{
            test_utils::{
                config_helper::test_config_base_dir,
                docker_runner::DockerTestRunnerBuilder, run_test_suites_and_cleanup,
                Suite,
            },
            GLOBAL_DIRECT_CONNECTOR,
        },
        tests::initialize,
    };

    use super::*;

    async fn get_hysteria_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let conf = test_config_dir.join("hysteria.json");
        let cert = test_config_dir.join("example.org.pem");
        let key = test_config_dir.join("example.org-key.pem");

        DockerTestRunnerBuilder::new()
            .image(IMAGE_HYSTERIA)
            .mounts(&[
                (conf.to_str().unwrap(), "/config.json"),
                (cert.to_str().unwrap(), "/home/ubuntu/my.crt"),
                (key.to_str().unwrap(), "/home/ubuntu/my.key"),
            ])
            .cmd(&["server"])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_hysteria() -> anyhow::Result<()> {
        initialize();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let port = 10002;

        let obfs = Some(Obfs::Salamander(SalamanderObfs {
            key: "beauty will save the world".to_owned().into(),
        }));

        let ports_gen = Some(
            PortGenerator::new(port)
                .parse_ports_str("")
                .map_err(|_| crate::Error::InvalidConfig("".into()))?,
        );

        let opts = HystOption {
            name: "test-hysteria".to_owned(),
            sni: "example.org".to_owned().into(),
            addr: (ip, port).into(),
            alpn: vec![],
            ca: None,
            fingerprint: None,
            skip_cert_verify: true,
            passwd: "passwd".to_owned(),
            ports: ports_gen,
            obfs,
            up_down: Some((100, 100)),
            ca_str: None,
            cwnd: None,
        };

        let handler = Arc::new(Handler::new(opts)?);
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(
            handler,
            get_hysteria_runner().await?,
            Suite::tcp_tests(),
        )
        .await
    }
}
