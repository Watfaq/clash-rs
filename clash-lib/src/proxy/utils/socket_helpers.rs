#[cfg(not(target_os = "android"))]
use super::platform::must_bind_socket_on_interface;
use crate::app::net::OutboundInterface;
use socket2::TcpKeepalive;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};
#[cfg(not(target_os = "android"))]
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
        debug!("binding tcp socket to interface: {:?}", iface);
        must_bind_socket_on_interface(&socket, &iface, family)?;
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
) -> std::io::Result<UdpSocket> {
    let (socket, family) = match src {
        Some(src) => {
            if src.is_ipv4() {
                debug!("resolved v4 socket for v4 src {src:?}");
                (
                    socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::DGRAM,
                        None,
                    )?,
                    socket2::Domain::IPV4,
                )
            } else {
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
        }
        None => {
            if let Some(iface) = iface.as_ref() {
                if iface.addr_v6.is_some() {
                    debug!("resolved v6 socket for v6 iface {:?}", iface.addr_v6);
                    (
                        socket2::Socket::new(
                            socket2::Domain::IPV6,
                            socket2::Type::DGRAM,
                            None,
                        )?,
                        socket2::Domain::IPV6,
                    )
                } else {
                    debug!("resolved v4 socket for v4 iface {:?}", iface.addr_v4);
                    (
                        socket2::Socket::new(
                            socket2::Domain::IPV4,
                            socket2::Type::DGRAM,
                            None,
                        )?,
                        socket2::Domain::IPV4,
                    )
                }
            } else {
                debug!("no src or iface provided, using default v4 socket");
                (
                    socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::DGRAM,
                        None,
                    )?,
                    socket2::Domain::IPV4,
                )
            }
        }
    };

    #[cfg(not(target_os = "android"))]
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

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}
