use std::{
    io::{self},
    net::{IpAddr, SocketAddr},
    ops::Deref,
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// A dual stack UDP socket. In linux dual stack is enabled by default for IPv6 socket,
/// and IPv4 address mapped from/to IPv6 address is done automatically.
/// In windows, Ipv4 mapping must be done manually.
pub struct DualSocket {
    inner: UdpSocket,
    pub dual_stack: bool,
}
impl DualSocket {
    pub fn new_bind(addr: SocketAddr, mut dual_stack: bool) -> io::Result<Self> {
        //let upstream = UdpSocket::bind(dst).await?;
        let socket = Socket::new(
            // Use socket2 for dualstack for windows compact
            if dual_stack || addr.ip().is_ipv6() {
                Domain::IPV6
            } else {
                Domain::IPV4
            },
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        if dual_stack {
            let _ = socket.set_only_v6(false).map_err(|x| {
                dual_stack = false;
                tracing::warn!("set dual stack for failed: {}", x);
            });
        };
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;

        let socket = UdpSocket::from_std(socket.into())?;

        Ok(Self {
            inner: socket,
            dual_stack,
        })
    }
    pub async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        let ip = match (self.dual_stack, addr.ip()) {
            (true, IpAddr::V4(ipv4_addr)) => IpAddr::V6(ipv4_addr.to_ipv6_mapped()),
            (_, ip) => ip,
        };
        self.inner.send_to(buf, (ip, addr.port())).await
    }
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (len, addr) = self.inner.recv_from(buf).await?;
        let ip = match (self.dual_stack, addr.ip()) {
            (true, ip_addr @ IpAddr::V6(ipv6_addr)) => ipv6_addr
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(ip_addr),
            (_, ip) => ip,
        };
        Ok((len, SocketAddr::new(ip, addr.port())))
    }
}

impl Deref for DualSocket {
    type Target = UdpSocket;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub fn to_ipv4_mapped(mut addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        ip_addr @ IpAddr::V6(ipv6_addr) => ipv6_addr
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(ip_addr),
        ip => ip,
    };
    addr.set_ip(ip);
    addr
}
