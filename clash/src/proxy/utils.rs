use crate::app::ThreadSafeDNSResolver;
use crate::proxy::AnyStream;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpSocket, UdpSocket};
use tokio::time::timeout;

pub async fn new_tcp_stream(
    dns_client: ThreadSafeDNSResolver,
    address: &str,
    port: u16,
    iface: Option<SocketAddr>,
    #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
) -> io::Result<AnyStream> {
    let dial_addr = dns_client
        .read()
        .await
        .resolve(address)
        .await?
        .ok_or(io::Error::new(
            io::ErrorKind::Other,
            format!("can't resolve dns: {}", address),
        ))?;
    let socket = match dial_addr {
        IpAddr::V4(_) => socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?,
        IpAddr::V6(_) => socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?,
    };

    if iface.is_some() {
        //TODO: bind iface name
        socket.bind(&iface.unwrap().into())?;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(packet_mark) = packet_mark {
        socket.set_mark(packet_mark)?;
    }

    socket.set_keepalive(true)?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    let stream = timeout(
        Duration::from_secs(10),
        TcpSocket::from_std_stream(socket.into()).connect((dial_addr, port).into()),
    )
    .await??;

    Ok(Box::new(stream))
}

pub async fn new_udp_socket(
    src: &SocketAddr,
    iface: Option<SocketAddr>,
    #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    _packet_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let socket = if src.is_ipv4() {
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?
    } else {
        socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?
    };

    if iface.is_some() {
        socket.bind(&iface.unwrap().into())?;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(packet_mark) = packet_mark {
        socket.set_mark(packet_mark)?;
    }

    UdpSocket::from_std(socket.into())
}
