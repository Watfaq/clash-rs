use quinn::{
    Connection as QuinnConnection, Endpoint as QuinnEndpoint, ZeroRttAccepted,
};
use register_count::Counter;
use watfaq_config::OutboundCommonOptions;
use watfaq_error::{Result, anyhow};
use watfaq_resolver::AbstractResolver;
use watfaq_state::Context;
use watfaq_types::{Stack, TargetAddr, UdpPacket};
use watfaq_utils::which_stack_decision;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{Arc, atomic::AtomicU32},
    time::Duration,
};
use tokio::sync::RwLock as AsyncRwLock;
use tracing::debug;
use tuic_quinn::Connection as InnerConnection;
use uuid::Uuid;

pub struct TuicClient {
    pub ep: QuinnEndpoint,
    pub server: ServerAddr,
    pub uuid: Uuid,
    pub password: Arc<[u8]>,
    pub udp_relay_mode: UdpRelayMode,
    pub zero_rtt_handshake: bool,
    pub heartbeat: Duration,
    pub gc_interval: Duration,
    pub gc_lifetime: Duration,

    pub common: OutboundCommonOptions,
    pub ip: Option<IpAddr>,
}
impl TuicClient {
    pub async fn connect(
        &self,
        ctx: &Context,
        resolver: &impl AbstractResolver,
        rebind: bool,
    ) -> Result<Arc<TuicConnection>> {
        // if client and server don't match each other or forced to rebind,
        // then rebind local socket
        let connect_to = async {
            let server_ip = self.server.resolve(resolver).await?;
            let stack = which_stack_decision(
                self.common
                    .interface
                    .as_ref()
                    .unwrap_or(&ctx.default_iface.load()),
                self.common.stack_prefer.unwrap_or(ctx.stack_prefer.clone()),
                server_ip.into(),
            )
            .unwrap_or_default();
            let server_addr = match stack {
                Stack::V4 => {
                    SocketAddr::new(server_ip.0.expect("Unreachable").into(), 0)
                }
                Stack::V6 => {
                    SocketAddr::new(server_ip.1.expect("Unreachable").into(), 0)
                }
            };
            if rebind {
                // TODO allow override protector (when outbound specify
                // interface/fwmark)
                let socket: UdpSocket =
                    ctx.protector.new_udp_socket(stack).await?.into_std()?;
                debug!("try rebind endpoint UDP socket to {}", socket.local_addr()?);

                self.ep.rebind(socket).map_err(|err| {
                    anyhow!("failed to rebind endpoint UDP socket {}", err)
                })?;
            }

            tracing::trace!(
                "connecting to {} {} from {}",
                server_addr,
                self.server.server_name(),
                self.ep.local_addr().unwrap()
            );

            let conn = self.ep.connect(server_addr, self.server.server_name())?;
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
            Ok((conn, zero_rtt_accepted)) => Ok(TuicConnection::new(
                conn,
                zero_rtt_accepted,
                self.udp_relay_mode,
                self.uuid,
                self.password.clone(),
                self.heartbeat,
                self.gc_interval,
                self.gc_lifetime,
            )),
            Err(err) => Err(err),
        }
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
    pub local_addr: TargetAddr,
}

impl TuicConnection {
    pub fn check_open(&self) -> Result<()> {
        match self.conn.close_reason() {
            Some(err) => Err(err)?,
            None => Ok(()),
        }
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
            inner: InnerConnection::<tuic_quinn::side::Client>::new(conn),
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
}

impl ServerAddr {
    pub fn new(domain: String, port: u16, ip: Option<IpAddr>) -> Self {
        Self { domain, port, ip }
    }

    pub fn server_name(&self) -> &str {
        &self.domain
    }

    pub async fn resolve(
        &self,
        resolver: &impl AbstractResolver,
    ) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        if let Some(ip) = self.ip {
            match ip {
                IpAddr::V4(ipv4_addr) => Ok((Some(ipv4_addr), None)),
                IpAddr::V6(ipv6_addr) => Ok((None, Some(ipv6_addr))),
            }
        } else {
            let ip = resolver.resolve(self.domain.as_str(), false).await?;
            Ok(ip)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}
impl From<&str> for UdpRelayMode {
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

impl Default for CongestionControl {
    fn default() -> Self {
        Self::Cubic
    }
}

pub trait SocketAdderTrans {
    fn into_tuic(self) -> tuic::Address;
}
impl SocketAdderTrans for TargetAddr {
    fn into_tuic(self) -> tuic::Address {
        match self {
            TargetAddr::Ip(addr) => tuic::Address::SocketAddress(addr),
            TargetAddr::Domain(domain, port) => {
                tuic::Address::DomainAddress(domain, port)
            }
        }
    }
}
