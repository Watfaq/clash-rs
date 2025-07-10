mod codec;
mod congestion;
mod datagram;
mod salamander;
mod udp_hop;

use bytes::{Bytes, BytesMut};
use codec::Fragments;
use futures::{SinkExt, StreamExt};
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::{
    ClientConfig, Connection, TokioRuntime, crypto::rustls::QuicClientConfig,
};
use quinn_proto::TransportConfig;
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    path::PathBuf,
    pin::Pin,
    str::FromStr,
    sync::{Arc, RwLock, atomic::AtomicU32},
    task::{Context, Poll},
};

use rustls::ClientConfig as RustlsClientConfig;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::tls::DefaultTlsVerifier,
    session::{Session, SocksAddr},
};
use tracing::{debug, trace, warn};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    converters::hysteria2::PortGenerator, datagram::UdpPacket,
    utils::new_udp_socket,
};

use self::{
    codec::Hy2TcpCodec,
    congestion::{Burtal, DynController},
    datagram::{HysteriaDatagramOutbound, UdpSession},
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
    pub udp_mtu: Option<u32>,
    pub disable_mtu_discovery: bool,
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
    conn: Mutex<Option<Arc<HysteriaConnection>>>,
    next_session_id: AtomicU32,
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

    pub fn new(opts: HystOption) -> Self {
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
        if opts.disable_mtu_discovery {
            tracing::debug!("disable mtu discovery");
            transport.mtu_discovery_config(None);
        }
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

        Self {
            opts,
            ep_config,
            client_config,
            next_session_id: AtomicU32::new(0),
            conn: Mutex::new(None),
            guard: Mutex::new(None),
            support_udp: RwLock::new(true),
        }
    }

    // connect and auth
    async fn new_authed_connection_inner(
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
                sess.iface.as_ref(),
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

    pub async fn new_authed_connection(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<Arc<HysteriaConnection>> {
        let mut quinn_conn_lock = self.conn.lock().await;

        match (*quinn_conn_lock).as_ref().filter(|s| {
            match s.conn.close_reason() {
                // rust should have inspect method on Option and Result!
                Some(reason) => {
                    tracing::debug!("old connection closed: {:?}", reason);
                    false
                }
                None => true,
            }
        }) {
            Some(s) => Ok(s.clone()),
            None => {
                let (session, guard) = self
                    .new_authed_connection_inner(sess, resolver)
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "connect to {} failed: {}",
                            self.opts.addr, e
                        ))
                    })?;
                let session = Arc::new(session);
                let hyst_conn = HysteriaConnection::new_with_task_loop(
                    session,
                    self.opts.udp_mtu,
                );
                *quinn_conn_lock = Some(hyst_conn.clone());
                *self.guard.lock().await = Some(guard);
                Ok(hyst_conn)
            }
        }
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

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let authed_conn = self.new_authed_connection(sess, resolver.clone()).await?;
        let hy_stream = authed_conn.connect_tcp(sess).await?;
        Ok(Box::new(ChainedStreamWrapper::new(Box::new(hy_stream))))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let authed_conn = self.new_authed_connection(sess, resolver.clone()).await?;
        let next_session_id = self
            .next_session_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let hy_datagram = authed_conn.connect_udp(sess, next_session_id).await;
        let s = ChainedDatagramWrapper::new(hy_datagram);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }
}

pub struct HysteriaConnection {
    pub conn: Arc<quinn::Connection>,
    pub udp_sessions: Arc<tokio::sync::Mutex<HashMap<u32, UdpSession>>>,

    // config
    pub udp_mtu: Option<usize>,
}

impl HysteriaConnection {
    pub fn new_with_task_loop(
        conn: Arc<quinn::Connection>,
        udp_mtu: Option<u32>,
    ) -> Arc<Self> {
        let s = Arc::new(Self {
            conn,
            udp_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            udp_mtu: udp_mtu.map(|x| x as usize),
        });
        tokio::spawn(Self::spawn_tasks(s.clone()));

        s
    }

    async fn spawn_tasks(self: Arc<Self>) {
        let err = loop {
            tokio::select! {
                res = self.conn.read_datagram() => {
                    match res {
                        Ok(pkt) => self.clone().recv_packet(pkt).await,
                        Err(e) => {
                            tracing::error!("hysteria2 read datagram error: {}", e);
                            break e;
                        }
                    }
                }
            }
        };
        tracing::warn!("hysteria2 connection error: {:?}", err);
    }

    pub async fn connect_tcp(&self, sess: &Session) -> std::io::Result<HystStream> {
        let (mut tx, mut rx) = self.conn.open_bi().await?;
        tokio_util::codec::FramedWrite::new(&mut tx, Hy2TcpCodec)
            .send(&sess.destination)
            .await?;

        match tokio_util::codec::FramedRead::new(&mut rx, Hy2TcpCodec)
            .next()
            .await
        {
            Some(Ok(resp)) => {
                if resp.status != 0x00 {
                    return Err(std::io::Error::other(format!(
                        "server response error, msg: {:?}",
                        resp.msg
                    )));
                } else {
                    debug!(
                        "hysteria2 tcp request success: status: {}, msg: {:?}",
                        resp.status, resp.msg
                    );
                }
            }
            _ => {
                return Err(std::io::Error::other(
                    "not receive hysteria2 response from server",
                ));
            }
        };

        Ok(HystStream { send: tx, recv: rx })
    }

    pub async fn connect_udp(
        self: Arc<Self>,
        sess: &Session,
        session_id: u32,
    ) -> HysteriaDatagramOutbound {
        tracing::trace!(
            "hysteria connect udp, sess: {:?}, session_id: {}",
            sess,
            session_id
        );
        HysteriaDatagramOutbound::new(
            session_id,
            self.clone(),
            sess.destination.clone(),
        )
        .await
    }

    pub fn send_packet(
        &self,
        pkt: Bytes,
        addr: SocksAddr,
        session_id: u32,
        pkt_id: u16,
    ) -> std::io::Result<()> {
        let max_frag_size = match self.udp_mtu.or(self.conn.max_datagram_size()) {
            Some(x) => x,
            None => {
                return Err(std::io::Error::other(
                    "hysteria2 udp mtu not set, please check your \
                     disable_mtu_discovery and udp_mtu option",
                ));
            }
        };
        let fragments = Fragments::new(session_id, pkt_id, addr, max_frag_size, pkt);
        for frag in fragments {
            self.conn
                .send_datagram(frag)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }
        Ok(())
    }

    pub async fn recv_packet(self: Arc<Self>, pkt: Bytes) {
        let mut buf: BytesMut = pkt.into();
        let pkt = codec::HysUdpPacket::decode(&mut buf).unwrap();
        let session_id = pkt.session_id;
        let mut udp_sessions = self.udp_sessions.lock().await;
        match udp_sessions.get_mut(&session_id) {
            Some(session) => {
                if let Some(pkt) = session.feed(pkt) {
                    let _ = session
                        .incoming
                        .send(UdpPacket {
                            data: pkt.data,
                            src_addr: pkt.addr,
                            dst_addr: session.local_addr.clone(),
                        })
                        .await;
                }
            }
            _ => {
                tracing::warn!("hysteria2 udp session not found: {}", session_id);
            }
        }
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
            GLOBAL_DIRECT_CONNECTOR,
            test_utils::{
                Suite, config_helper::test_config_base_dir,
                docker_runner::DockerTestRunnerBuilder, run_test_suites_and_cleanup,
            },
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
            udp_mtu: None,
            disable_mtu_discovery: false,
        };

        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(
            handler,
            get_hysteria_runner().await?,
            Suite::all(),
        )
        .await
    }
}
