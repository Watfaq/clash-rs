use super::platform::must_bind_socket_on_interface;
use crate::app::net::OutboundInterface;

use futures::io;
use socket2::TcpKeepalive;
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};
use tracing::{debug, error, instrument, trace};

pub fn apply_tcp_options(s: &TcpStream) -> std::io::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        let sock_ref = socket2::SockRef::from(s);
        sock_ref.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )?;
    }
    #[cfg(target_os = "windows")]
    {
        let sock_ref = socket2::SockRef::from(s);
        sock_ref.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        )?;
    }
    // Disable Nagle's algorithm so that small writes (e.g. HTTP response
    // headers arriving from the proxy side) are forwarded to the client
    // immediately without waiting for a full TCP segment.
    s.set_nodelay(true)
}

#[instrument(skip(so_mark))]
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
    debug!("created tcp socket");

    if !cfg!(target_os = "android")
        && let Some(iface) = iface
    {
        must_bind_socket_on_interface(&socket, iface, family)?;
        trace!("tcp socket bound to interface: {socket:?}");
    }

    #[cfg(not(target_os = "android"))]
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

#[instrument(skip(so_mark))]
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
            let domain = socket2::Domain::for_address(family_hint);
            (
                socket2::Socket::new(domain, socket2::Type::DGRAM, None)?,
                domain,
            )
        }
        (None, Some(src), _) if src.is_ipv6() => (
            try_create_dualstack_socket(src, socket2::Type::DGRAM)?.0,
            socket2::Domain::IPV6,
        ),
        (None, _, Some(iface)) if iface.addr_v6.is_some() => (
            socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV6,
        ),
        _ => (
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV4,
        ),
    };
    debug!("created udp socket");

    if !cfg!(target_os = "android") {
        match (src, iface) {
            (_, Some(iface)) => {
must_bind_socket_on_interface(&socket, iface, family).inspect_err(
                    |x| {
                        error!("failed to bind socket to interface: {}", x);
                    },
                )?;
                // binding is not necessary for linux but is required on windows
                // Without binding local_addr can't be obtained by system call
                // which is required on quinn.
                #[cfg(target_os = "windows")]
                if let Some(addr) = src {
                    socket.bind(&socket2::SockAddr::from(addr))?;
                }

                trace!(iface = ?iface, "udp socket bound: {socket:?}");
            }
            (Some(src), None) => {
                socket.bind(&src.into())?;
                trace!(src = ?src, "udp socket bound: {socket:?}");
            }
            (None, None) => {
                // On Windows, UDP sockets must be bound to get a valid local_addr
                // which is required for some operations (e.g., quinn/QUIC)
                #[cfg(target_os = "windows")]
                {
                    let bind_addr = match family {
                        socket2::Domain::IPV4 => {
                            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
                        }
                        socket2::Domain::IPV6 => {
                            "[::]:0".parse::<SocketAddr>().unwrap()
                        }
                        _ => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
                    };
                    socket.bind(&socket2::SockAddr::from(bind_addr))?;
                    trace!(addr = ?bind_addr, "udp socket bound to default address on Windows: {socket:?}");
                }
                #[cfg(not(target_os = "windows"))]
                trace!("udp socket not bound to any specific address: {socket:?}");
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

/// Create a dual-stack UDP socket bound to `[::]`, falling back to an IPv4
/// socket bound to `0.0.0.0` if IPv6 is unavailable.  The resulting socket
/// can send to both IPv4 and IPv6 destinations without EAFNOSUPPORT, which
/// is required when one outbound socket is reused across destinations with
/// different address families (e.g. in the DIRECT handler).
pub fn new_dual_stack_udp_socket(
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<UdpSocket> {
    let dual_stack = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let ipv4_only = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    let (socket, bind_addr) =
        match try_create_dualstack_socket(dual_stack, socket2::Type::DGRAM) {
            Ok((s, true)) => (s, dual_stack),
            Ok((_, false)) | Err(_) => (
                socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    None,
                )?,
                ipv4_only,
            ),
        };

    if let Some(iface) = iface {
        let family = socket2::Domain::for_address(bind_addr);
        must_bind_socket_on_interface(&socket, iface, family).inspect_err(|x| {
            error!("failed to bind socket to interface: {}", x);
        })?;
    } else {
        socket.bind(&bind_addr.into())?;
    }

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
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
