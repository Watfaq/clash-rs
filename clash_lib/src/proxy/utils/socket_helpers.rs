use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use socket2::TcpKeepalive;
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};

#[cfg(target_os = "windows")]
use tracing::warn;
use tracing::{debug, error};

use super::Interface;
use crate::{app::dns::ThreadSafeDNSResolver, proxy::AnyStream};

pub fn apply_tcp_options(s: TcpStream) -> std::io::Result<TcpStream> {
    #[cfg(not(target_os = "windows"))]
    {
        let s = socket2::Socket::from(s.into_std()?);
        s.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )?;
        TcpStream::from_std(s.into())
    }
    #[cfg(target_os = "windows")]
    {
        let s = socket2::Socket::from(s.into_std()?);
        s.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        )?;
        TcpStream::from_std(s.into())
    }
}

fn must_bind_socket_on_interface(socket: &socket2::Socket, iface: &Interface) -> io::Result<()> {
    match iface {
        // TODO: should this be ever used vs. calling .bind(2) from the caller side?
        Interface::IpAddr(ip) => socket.bind(&SocketAddr::new(*ip, 0).into()),
        Interface::Name(name) => {
            #[cfg(target_vendor = "apple")]
            {
                socket.bind_device_by_index_v4(std::num::NonZeroU32::new(unsafe {
                    libc::if_nametoindex(name.as_str().as_ptr() as *const _)
                }))
            }
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            {
                socket.bind_device(Some(name.as_bytes()))
            }
            #[cfg(target_os = "windows")]
            {
                warn!(
                    "binding to interface[{}] by name is not supported on Windows",
                    name
                );
                Ok(())
            }
        }
    }
}

pub async fn new_tcp_stream<'a>(
    resolver: ThreadSafeDNSResolver,
    address: &'a str,
    port: u16,
    iface: Option<&'a Interface>,
    #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
) -> io::Result<AnyStream> {
    let dial_addr = resolver
        .resolve(address, false)
        .await
        .map_err(|v| io::Error::new(io::ErrorKind::Other, format!("dns failure: {}", v)))?
        .ok_or(io::Error::new(
            io::ErrorKind::Other,
            format!("can't resolve dns: {}", address),
        ))?;

    debug!(
        "dialing {}[{}]:{} via {:?}",
        address, dial_addr, port, iface
    );

    let socket = match (dial_addr, resolver.ipv6()) {
        (IpAddr::V4(_), _) => {
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?
        }
        (IpAddr::V6(_), true) => {
            socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?
        }
        (IpAddr::V6(_), false) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("ipv6 is disabled, can't dial {}", address),
            ))
        }
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

    debug!("connected to {}[{}]:{}", address, dial_addr, port);
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

    match (src, iface) {
        (Some(_), Some(iface)) => {
            debug!("both src and iface are set, iface will be used: {:?}", src);
            must_bind_socket_on_interface(&socket, iface).inspect_err(|x| {
                error!("failed to bind socket to interface: {}", x);
            })?;
        }
        (Some(src), None) => {
            debug!("binding socket to: {:?}", src);
            socket.bind(&(*src).into())?;
        }
        (None, Some(iface)) => {
            debug!("binding socket to interface: {:?}", iface);
            must_bind_socket_on_interface(&socket, iface).inspect_err(|x| {
                error!("failed to bind socket to interface: {}", x);
            })?;
        }
        (None, None) => {
            debug!("not binding socket to any address or interface");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(packet_mark) = packet_mark {
        socket.set_mark(packet_mark)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use tokio::{net::TcpSocket, time::timeout};

    #[tokio::test]
    #[ignore = "not a real test"]
    async fn test_connect_tcp() {
        let mut futs = vec![];

        for i in 0..100 {
            futs.push(tokio::spawn(async move {
                let now = std::time::Instant::now();
                let socket =
                    socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
                        .unwrap();

                timeout(
                    Duration::from_secs(10),
                    TcpSocket::from_std_stream(socket.into())
                        .connect(("1.1.1.1".parse::<IpAddr>().unwrap(), 443).into()),
                )
                .await
                .unwrap()
                .unwrap();

                println!("fut {} took {:?}", i, now.elapsed().as_millis());
            }));
        }

        futures::future::join_all(futs).await;
    }
}
