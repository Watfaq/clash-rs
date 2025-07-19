use super::platform::must_bind_socket_on_interface;
use crate::{
    app::{dns::ThreadSafeDNSResolver, net::OutboundInterface},
    session::Session,
};

use futures::io;
use socket2::TcpKeepalive;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};
use tracing::{debug, error};

pub fn apply_tcp_options(s: &TcpStream) -> std::io::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        let s = socket2::SockRef::from(s);
        s.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )
    }
    #[cfg(target_os = "windows")]
    {
        let s = socket2::SockRef::from(s);
        s.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        )
    }
}

#[allow(unused_variables)]
pub async fn new_tcp_stream(
    endpoint: SocketAddr,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    let (socket, family) = match endpoint {
        SocketAddr::V4(_) => (
            socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                None,
            )?,
            socket2::Domain::IPV4,
        ),
        SocketAddr::V6(_) => (
            socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                None,
            )?,
            socket2::Domain::IPV6,
        ),
    };

    #[cfg(not(target_os = "android"))]
    if let Some(iface) = iface {
        debug!("binding tcp socket to interface: {iface:?}, family: {family:?}");
        must_bind_socket_on_interface(&socket, iface, family)?;
    }

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_keepalive(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_nonblocking(true)?;

    timeout(
        Duration::from_secs(10),
        TcpSocket::from_std_stream(socket.into()).connect(endpoint),
    )
    .await?
}

pub async fn new_udp_socket(
    src: Option<SocketAddr>,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
    // Optional family hint for the socket.
    // If not provided, the family will be determined based on the source
    // address or interface.
    family_hint: Option<std::net::SocketAddr>,
) -> std::io::Result<UdpSocket> {
    // Determine the socket family based on the source address or interface
    // logic:
    // - If family_hint is provided, use it.
    // - If src is provided and is IPv6, use IPv6.
    // - If iface is provided and is IPv6, use IPv6.
    // - Otherwise, default to IPv4.
    let (socket, family) = match (family_hint, src, iface) {
        (Some(family_hint), ..) => {
            debug!("using provided family hint: {family_hint:?}");
            let domain = socket2::Domain::for_address(family_hint);
            (
                socket2::Socket::new(domain, socket2::Type::DGRAM, None)?,
                domain,
            )
        }
        (None, Some(src), _) if src.is_ipv6() => {
            debug!("resolved v6 socket for v6 src {src:?}");
            (
                socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    None,
                )?,
                socket2::Domain::IPV6,
            )
        }
        (None, _, Some(iface)) if iface.addr_v6.is_some() => {
            debug!("resolved v6 socket for v6 iface {iface:?}");
            (
                socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    None,
                )?,
                socket2::Domain::IPV6,
            )
        }
        _ => {
            debug!("defaulting to v4 socket");
            (
                socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    None,
                )?,
                socket2::Domain::IPV4,
            )
        }
    };

    if !cfg!(target_os = "android") {
        match (src, iface) {
            (Some(_), Some(iface)) => {
                debug!("both src and iface are set, iface will be used: {iface:?}");
                must_bind_socket_on_interface(&socket, iface, family).inspect_err(
                    |x| {
                        error!("failed to bind socket to interface: {}", x);
                    },
                )?;
            }
            (Some(src), None) => {
                debug!("binding socket to: {:?}", src);
                socket.bind(&src.into())?;
            }
            (None, Some(iface)) => {
                debug!("binding udp socket to interface: {:?}", iface);
                must_bind_socket_on_interface(&socket, iface, family).inspect_err(
                    |x| {
                        error!("failed to bind socket to interface: {}", x);
                    },
                )?;
            }
            (None, None) => {
                debug!("not binding socket to any address or interface");
            }
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

pub async fn family_hint_for_session(
    sess: &Session,
    resolver: &ThreadSafeDNSResolver,
) -> Option<std::net::SocketAddr> {
    if let Some(resolved_ip) = sess.resolved_ip {
        Some(SocketAddr::new(resolved_ip, sess.destination.port()))
    } else if let Some(host) = sess.destination.ip() {
        Some(SocketAddr::new(host, sess.destination.port()))
    } else {
        let host = sess.destination.host();
        resolver
            .resolve_v6(&host, false)
            .await
            .map(|ip| {
                ip.map(|ip| SocketAddr::new(ip.into(), sess.destination.port()))
            })
            .ok()?
    }
}

/// Convert ipv6 mapped ipv4 address back to ipv4. Other address remain
/// unchanged. e.g. ::ffff:127.0.0.1 -> 127.0.0.1
pub trait ToCanonical {
    fn to_canonical(self) -> SocketAddr;
}

impl ToCanonical for SocketAddr {
    fn to_canonical(mut self) -> SocketAddr {
        self.set_ip(self.ip().to_canonical());
        self
    }
}

/// Create dualstack socket if it can
/// If failed, fallback to single stack silently
pub fn try_create_dualstack_socket(
    addr: SocketAddr,
    tcp_or_udp: socket2::Type,
) -> std::io::Result<(socket2::Socket, bool)> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let mut dualstack = false;
    let socket = socket2::Socket::new(domain, tcp_or_udp, None)?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        if let Err(e) = socket.set_only_v6(false) {
            // If setting dualstack fails, fallback to single stack
            tracing::warn!(
                "dualstack not supported, falling back to ipv6 only: {e}"
            );
        } else {
            dualstack = true;
        }
    };
    Ok((socket, dualstack))
}

pub fn try_create_dualstack_tcplistener(
    addr: SocketAddr,
) -> io::Result<TcpListener> {
    let (socket, _dualstack) =
        try_create_dualstack_socket(addr, socket2::Type::STREAM)?;

    socket.set_nonblocking(true)?;
    // For fast restart avoid Address In Use Error
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let listener = TcpListener::from_std(socket.into())?;
    Ok(listener)
}
