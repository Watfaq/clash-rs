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

use tracing::{debug, error};

use super::{platform::must_bind_socket_on_interface, Interface};
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

pub async fn new_simple_tcp_stream(
    endpoint: SocketAddr,
    iface: Option<Interface>,
    #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
) -> io::Result<TcpStream> {
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

    if let Some(iface) = iface {
        debug!("binding tcp socket to interface: {:?}", iface);
        must_bind_socket_on_interface(&socket, &iface, family)?;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(packet_mark) = packet_mark {
        socket.set_mark(packet_mark)?;
    }

    socket.set_keepalive(true)?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    timeout(
        Duration::from_secs(10),
        TcpSocket::from_std_stream(socket.into()).connect(endpoint),
    )
    .await?
}

/// This should get replaced with `new_simple_tcp_stream` in the future
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
        .map_err(|v| {
            io::Error::new(io::ErrorKind::Other, format!("dns failure: {}", v))
        })?
        .ok_or(io::Error::new(
            io::ErrorKind::Other,
            format!("can't resolve dns: {}", address),
        ))?;

    debug!(
        "dialing {}[{}]:{} via iface {:?}",
        address, dial_addr, port, iface
    );

    let (socket, family) = match (dial_addr, resolver.ipv6()) {
        (IpAddr::V4(_), _) => (
            socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                None,
            )?,
            socket2::Domain::IPV4,
        ),
        (IpAddr::V6(_), true) => (
            socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                None,
            )?,
            socket2::Domain::IPV6,
        ),
        (IpAddr::V6(_), false) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("ipv6 is disabled, can't dial {}", address),
            ))
        }
    };

    if let Some(iface) = iface {
        debug!("binding tcp socket to interface: {:?}", iface);
        must_bind_socket_on_interface(&socket, iface, family)?;
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
    src: Option<SocketAddr>,
    iface: Option<Interface>,
    #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
) -> io::Result<UdpSocket> {
    let (socket, family) = match src {
        Some(src) => {
            if src.is_ipv4() {
                (
                    socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::DGRAM,
                        None,
                    )?,
                    socket2::Domain::IPV4,
                )
            } else {
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
        None => (
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV4,
        ),
    };

    match (src, iface) {
        (Some(_), Some(iface)) => {
            debug!("both src and iface are set, iface will be used: {:?}", src);
            must_bind_socket_on_interface(&socket, &iface, family).inspect_err(
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
            must_bind_socket_on_interface(&socket, &iface, family).inspect_err(
                |x| {
                    error!("failed to bind socket to interface: {}", x);
                },
            )?;
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
                let socket = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    None,
                )
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
