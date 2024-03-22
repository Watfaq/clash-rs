use crate::session::SocksAddr as ClashSocksAddr;
use anyhow::Result;
use quinn::Connection as QuinnConnection;
use quinn::{Endpoint as QuinnEndpoint, ZeroRttAccepted};
use register_count::Counter;
use std::collections::HashMap;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    str::FromStr,
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};
use tokio::sync::RwLock as AsyncRwLock;
use tuic_quinn::Connection as InnerConnection;
use uuid::Uuid;

use crate::proxy::datagram::UdpPacket;

pub struct TuicEndpoint {
    pub ep: QuinnEndpoint,
    pub server: ServerAddr,
    pub uuid: Uuid,
    pub password: Arc<[u8]>,
    pub udp_relay_mode: UdpRelayMode,
    pub zero_rtt_handshake: bool,
    pub heartbeat: Duration,
    pub gc_interval: Duration,
    pub gc_lifetime: Duration,
}
impl TuicEndpoint {
    pub async fn connect(&self) -> Result<TuicConnection> {
        let mut last_err = None;

        for addr in self.server.resolve().await? {
            let connect_to = async {
                let match_ipv4 =
                    addr.is_ipv4() && self.ep.local_addr().map_or(false, |addr| addr.is_ipv4());
                let match_ipv6 =
                    addr.is_ipv6() && self.ep.local_addr().map_or(false, |addr| addr.is_ipv6());

                if !match_ipv4 && !match_ipv6 {
                    let bind_addr = if addr.is_ipv4() {
                        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
                    } else {
                        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
                    };

                    self.ep
                        .rebind(UdpSocket::bind(bind_addr).map_err(|err| {
                            anyhow!("failed to create endpoint UDP socket {}", err)
                        })?)
                        .map_err(|err| anyhow!("failed to rebind endpoint UDP socket {}", err))?;
                }

                tracing::trace!("Connect to {} {}", addr, self.server.server_name());
                let conn = self.ep.connect(addr, self.server.server_name())?;
                let (conn, zero_rtt_accepted) = if self.zero_rtt_handshake {
                    match conn.into_0rtt() {
                        Ok((conn, zero_rtt_accepted)) => (conn, Some(zero_rtt_accepted)),
                        Err(conn) => (conn.await?, None),
                    }
                } else {
                    (conn.await?, None)
                };

                Ok((conn, zero_rtt_accepted))
            };

            match connect_to.await {
                Ok((conn, zero_rtt_accepted)) => {
                    return Ok(TuicConnection::new(
                        conn,
                        zero_rtt_accepted,
                        self.udp_relay_mode,
                        self.uuid,
                        self.password.clone(),
                        self.heartbeat,
                        self.gc_interval,
                        self.gc_lifetime,
                    ));
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or(anyhow!("dns resolve")))
    }
}

#[derive(Clone)]
pub struct TuicConnection {
    pub conn: QuinnConnection,
    pub inner: InnerConnection<tuic_quinn::side::Client>,
    pub uuid: Uuid,
    pub password: Arc<[u8]>,
    pub remote_uni_stream_cnt: Counter,
    pub remote_bi_stream_cnt: Counter,
    pub max_concurrent_uni_streams: Arc<AtomicU32>,
    pub max_concurrent_bi_streams: Arc<AtomicU32>,
    pub udp_relay_mode: UdpRelayMode,
    pub udp_sessions: Arc<AsyncRwLock<HashMap<u16, UdpSession>>>,
}

pub struct UdpSession {
    pub incoming: tokio::sync::mpsc::Sender<UdpPacket>,
    pub local_addr: ClashSocksAddr,
}

impl TuicConnection {
    pub fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }
    fn new(
        conn: QuinnConnection,
        zero_rtt_accepted: Option<ZeroRttAccepted>,
        udp_relay_mode: UdpRelayMode,
        uuid: Uuid,
        password: Arc<[u8]>,
        heartbeat: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) -> Self {
        let conn = Self {
            conn: conn.clone(),
            inner: InnerConnection::<tuic_quinn::side::Client>::new(conn),
            uuid,
            password,
            udp_relay_mode,
            remote_uni_stream_cnt: Counter::new(),
            remote_bi_stream_cnt: Counter::new(),
            // TODO: seems tuic dynamicly adjust the size of max concurrent streams, is it necessary to configure the stream size?
            max_concurrent_uni_streams: Arc::new(AtomicU32::new(32)),
            max_concurrent_bi_streams: Arc::new(AtomicU32::new(32)),
            udp_sessions: Arc::new(AsyncRwLock::new(HashMap::new())),
        };

        tokio::spawn(
            conn.clone()
                .init(zero_rtt_accepted, heartbeat, gc_interval, gc_lifetime),
        );

        conn
    }
    async fn init(
        self,
        zero_rtt_accepted: Option<ZeroRttAccepted>,
        heartbeat: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) {
        tracing::info!("connection established");

        // TODO reduct spawn
        tokio::spawn(self.clone().tuic_auth(zero_rtt_accepted));
        tokio::spawn(self.clone().heartbeat(heartbeat));
        tokio::spawn(self.clone().collect_garbage(gc_interval, gc_lifetime));

        let err = loop {
            tokio::select! {
                res = self.accept_uni_stream() => match res {
                    Ok((recv, reg)) => tokio::spawn(self.clone().handle_uni_stream(recv, reg)),
                    Err(err) => break err,
                },
                res = self.accept_bi_stream() => match res {
                    Ok((send, recv, reg)) => tokio::spawn(self.clone().handle_bi_stream(send, recv, reg)),
                    Err(err) => break err,
                },
                res = self.accept_datagram() => match res {
                    Ok(dg) => tokio::spawn(self.clone().handle_datagram(dg)),
                    Err(err) => break err,
                },
            };
        };

        tracing::warn!("connection error: {err}");
    }

    async fn collect_garbage(self, gc_interval: Duration, gc_lifetime: Duration) {
        let mut interval = tokio::time::interval(gc_interval);
        loop {
            interval.tick().await;
            if self.is_closed() {
                break;
            }
            tracing::trace!("[gc]");
            self.inner.collect_garbage(gc_lifetime);
        }
    }
}

pub struct ServerAddr {
    domain: String,
    port: u16,
    ip: Option<IpAddr>,
}
impl ServerAddr {
    pub fn new(domain: String, port: u16, ip: Option<IpAddr>) -> Self {
        Self { domain, port, ip }
    }

    pub fn server_name(&self) -> &str {
        &self.domain
    }
    // TODO change to clash dns?
    pub async fn resolve(&self) -> Result<impl Iterator<Item = SocketAddr>> {
        if let Some(ip) = self.ip {
            Ok(vec![SocketAddr::from((ip, self.port))].into_iter())
        } else {
            Ok(tokio::net::lookup_host((self.domain.as_str(), self.port))
                .await?
                .collect::<Vec<_>>()
                .into_iter())
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

impl FromStr for UdpRelayMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("native") {
            Ok(Self::Native)
        } else if s.eq_ignore_ascii_case("quic") {
            Ok(Self::Quic)
        } else {
            Err("invalid UDP relay mode")
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}
impl From<&str> for CongestionControl {
    fn from(s: &str) -> Self {
        if s.eq_ignore_ascii_case("cubic") {
            Self::Cubic
        } else if s.eq_ignore_ascii_case("new_reno") || s.eq_ignore_ascii_case("newreno") {
            Self::NewReno
        } else if s.eq_ignore_ascii_case("bbr") {
            Self::Bbr
        } else {
            tracing::warn!("Unknown congestion controller {s}. Use default controller");
            Self::default()
        }
    }
}

impl Default for CongestionControl {
    fn default() -> Self {
        Self::Cubic
    }
}

pub trait SocketAdderTrans {
    fn into_tuic(self) -> tuic::Address;
}
impl SocketAdderTrans for crate::session::SocksAddr {
    fn into_tuic(self) -> tuic::Address {
        use crate::session::SocksAddr;
        match self {
            SocksAddr::Ip(addr) => tuic::Address::SocketAddress(addr),
            SocksAddr::Domain(domain, port) => tuic::Address::DomainAddress(domain, port),
        }
    }
}
