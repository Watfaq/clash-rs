use crate::{
    app::{dns::ThreadSafeDNSResolver, net::DEFAULT_OUTBOUND_INTERFACE},
    proxy::{datagram::UdpPacket, utils::new_udp_socket},
    session::SocksAddr as ClashSocksAddr,
};
use anyhow::{Result, anyhow};
use quinn::{
    Connection as QuinnConnection, Endpoint as QuinnEndpoint, ZeroRttAccepted,
};
use register_count::Counter;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::AtomicU32},
    time::Duration,
};
use tokio::sync::RwLock as AsyncRwLock;
use tracing::debug;
use tuic_core::quinn::Connection as InnerConnection;
use uuid::Uuid;

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
    pub async fn connect(
        &self,
        resolver: &ThreadSafeDNSResolver,
        rebind: bool,
    ) -> Result<Arc<TuicConnection>> {
        let remote_addr = self.server.resolve(resolver).await?;
        let connect_to = async {
            // if client and server don't match each other or forced to rebind,
            // then rebind local socket
            if rebind {
                debug!("rebinding endpoint UDP socket");

                let socket = {
                    let iface = DEFAULT_OUTBOUND_INTERFACE.read().await;
                    new_udp_socket(
                        None,
                        iface.as_ref(),
                        #[cfg(target_os = "linux")]
                        None,
                        self.server
                            .ip
                            .map(|ip| SocketAddr::new(ip, self.server.port)),
                    )
                    .await?
                };

                debug!("rebound endpoint UDP socket to {}", socket.local_addr()?);

                self.ep.rebind(socket.into_std()?).map_err(|err| {
                    anyhow!("failed to rebind endpoint UDP socket {}", err)
                })?;
            }

            tracing::trace!(
                "connecting to {} {} from {}",
                remote_addr,
                self.server.server_name(),
                self.ep.local_addr().unwrap()
            );

            let conn = self.ep.connect(remote_addr, self.server.server_name())?;
            let (conn, zero_rtt_accepted) = if self.zero_rtt_handshake {
                match conn.into_0rtt() {
                    Ok((conn, zero_rtt_accepted)) => (conn, Some(zero_rtt_accepted)),
                    Err(conn) => (conn.await?, None),
                }
            } else {
                (conn.await?, None)
            };

            anyhow::Ok((conn, zero_rtt_accepted))
        };

        let (conn, zero_rtt_accepted) = connect_to.await?;
        Ok(TuicConnection::new(
            conn,
            zero_rtt_accepted,
            self.udp_relay_mode,
            self.uuid,
            self.password.clone(),
            self.heartbeat,
            self.gc_interval,
            self.gc_lifetime,
        ))
    }
}

#[derive(Clone)]
pub struct TuicConnection {
    pub conn: QuinnConnection,
    pub inner: InnerConnection<tuic_core::quinn::side::Client>,
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
    pub fn check_open(&self) -> Result<()> {
        self.conn
            .close_reason()
            .map_or(Ok(()), |err| Err(err.into()))
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        conn: QuinnConnection,
        zero_rtt_accepted: Option<ZeroRttAccepted>,
        udp_relay_mode: UdpRelayMode,
        uuid: Uuid,
        password: Arc<[u8]>,
        heartbeat: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) -> Arc<Self> {
        let conn = Self {
            conn: conn.clone(),
            inner: InnerConnection::<tuic_core::quinn::side::Client>::new(conn),
            uuid,
            password,
            udp_relay_mode,
            remote_uni_stream_cnt: Counter::new(),
            remote_bi_stream_cnt: Counter::new(),
            // TODO: seems tuic dynamically adjust the size of max concurrent
            // streams, is it necessary to configure the stream size?
            max_concurrent_uni_streams: Arc::new(AtomicU32::new(32)),
            max_concurrent_bi_streams: Arc::new(AtomicU32::new(32)),
            udp_sessions: Arc::new(AsyncRwLock::new(HashMap::new())),
        };
        let conn = Arc::new(conn);
        tokio::spawn(conn.clone().init(
            zero_rtt_accepted,
            heartbeat,
            gc_interval,
            gc_lifetime,
        ));

        conn
    }

    async fn init(
        self: Arc<Self>,
        zero_rtt_accepted: Option<ZeroRttAccepted>,
        heartbeat: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) {
        tracing::info!("connection established");

        // TODO check the cancellation safety of tuic_auth
        tokio::spawn(self.clone().tuic_auth(zero_rtt_accepted));
        tokio::spawn(self.clone().cyclical_tasks(
            heartbeat,
            gc_interval,
            gc_lifetime,
        ));

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

        tracing::warn!("connection error: {err:?}");
    }
}

pub struct ServerAddr {
    domain: String,
    port: u16,
    ip: Option<IpAddr>,
    sni: Option<String>,
}
impl ServerAddr {
    pub fn new(
        domain: String,
        port: u16,
        ip: Option<IpAddr>,
        sni: Option<String>,
    ) -> Self {
        Self {
            domain,
            port,
            ip,
            sni,
        }
    }

    #[inline]
    pub fn server_name(&self) -> &str {
        self.sni.as_ref().unwrap_or(&self.domain)
    }

    pub async fn resolve(
        &self,
        resolver: &ThreadSafeDNSResolver,
    ) -> Result<SocketAddr> {
        if let Some(ip) = self.ip {
            Ok(SocketAddr::from((ip, self.port)))
        } else {
            let ip = resolver
                .resolve(self.domain.as_str(), false)
                .await?
                .ok_or(anyhow!("Resolve failed: unknown hostname"))?;
            Ok(SocketAddr::from((ip, self.port)))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}
impl From<&str> for UdpRelayMode {
    #[inline]
    fn from(s: &str) -> Self {
        if s.eq_ignore_ascii_case("native") {
            Self::Native
        } else if s.eq_ignore_ascii_case("quic") {
            Self::Quic
        } else {
            // TODO logging
            Self::Quic
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum CongestionControl {
    Cubic,
    NewReno,
    #[default]
    Bbr,
}
impl From<&str> for CongestionControl {
    #[inline]
    fn from(s: &str) -> Self {
        if s.eq_ignore_ascii_case("cubic") {
            Self::Cubic
        } else if s.eq_ignore_ascii_case("new_reno")
            || s.eq_ignore_ascii_case("newreno")
        {
            Self::NewReno
        } else if s.eq_ignore_ascii_case("bbr") {
            Self::Bbr
        } else {
            tracing::warn!(
                "Unknown congestion controller {s}. Use default controller"
            );
            Self::default()
        }
    }
}

pub trait SocketAdderTrans {
    fn into_tuic(self) -> tuic_core::Address;
}
impl SocketAdderTrans for crate::session::SocksAddr {
    #[inline]
    fn into_tuic(self) -> tuic_core::Address {
        use crate::session::SocksAddr;
        match self {
            SocksAddr::Ip(addr) => tuic_core::Address::SocketAddress(addr),
            SocksAddr::Domain(domain, port) => {
                tuic_core::Address::DomainAddress(domain, port)
            }
        }
    }
}
