use crate::app::ThreadSafeDNSResolver;
use crate::proxy::{AnyStream, ProxyStream};

use hyper::body::HttpBody;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpSocket, UdpSocket};
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub enum Interface {
    IpAddr(IpAddr),
    Name(String),
}

impl Interface {
    pub fn into_ip_addr(self) -> Option<IpAddr> {
        match self {
            Interface::IpAddr(ip) => Some(ip),
            Interface::Name(_) => None,
        }
    }

    pub fn into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            Interface::IpAddr(ip) => Some(SocketAddr::new(ip, 0)),
            Interface::Name(_) => None,
        }
    }

    pub fn into_iface_name(self) -> Option<String> {
        match self {
            Interface::IpAddr(_) => None,
            Interface::Name(iface) => Some(iface),
        }
    }
}

fn must_bind_socket_on_interface(socket: &socket2::Socket, iface: &Interface) -> io::Result<()> {
    match iface {
        // TODO: should this be ever used vs. calling .bind(2) from the caller side?
        Interface::IpAddr(ip) => socket.bind(&SocketAddr::new(ip.clone(), 0).into()),
        Interface::Name(name) => unsafe {
            #[cfg(target_vendor = "apple")]
            {
                socket.bind_device_by_index(std::num::NonZeroU32::new(unsafe {
                    libc::if_nametoindex(name.as_str().as_ptr() as *const _)
                }))
            }
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            {
                socket.bind_device(&name)
            }
            #[cfg(target_os = "windows")]
            {
                // TODO maybe fallback to IpAddr
            }
        },
    }
}

pub async fn new_tcp_stream(
    dns_client: ThreadSafeDNSResolver,
    address: &str,
    port: u16,
    iface: Option<&Interface>,
    #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
) -> io::Result<AnyStream> {
    let dial_addr = dns_client
        .read()
        .await
        .resolve(address)
        .await
        .map_err(|v| io::Error::new(io::ErrorKind::Other, "dns failure"))?
        .ok_or(io::Error::new(
            io::ErrorKind::Other,
            format!("can't resolve dns: {}", address),
        ))?;

    let socket = match dial_addr {
        IpAddr::V4(_) => socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?,
        IpAddr::V6(_) => socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?,
    };

    if let Some(iface) = iface {
        must_bind_socket_on_interface(&socket, iface)?;
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
    src: Option<&SocketAddr>,
    iface: Option<&Interface>,
    #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let socket = match src {
        Some(src) => {
            if src.is_ipv4() {
                socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?
            } else {
                socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?
            }
        }
        None => socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?,
    };

    if let Some(src) = src {
        socket.bind(&src.clone().into())?;
    }

    if let Some(iface) = iface {
        must_bind_socket_on_interface(&socket, iface)?;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(packet_mark) = packet_mark {
        socket.set_mark(packet_mark)?;
    }

    socket.set_broadcast(true)?;

    UdpSocket::from_std(socket.into())
}
