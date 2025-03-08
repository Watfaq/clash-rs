use std::{
    io, net::SocketAddr, os::windows::io::FromRawSocket, sync::Arc, time::Duration,
};

use enum_dispatch::enum_dispatch;
use socket2::{Protocol, SockRef, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use watfaq_error::Result;
use watfaq_types::{Proto, Stack};

mod protector_bind;

mod protector_callback;

mod platform;

pub use protector_bind::BindProtector;

#[enum_dispatch(AbstractProtector)]
pub enum Protector {
    Bind(protector_bind::BindProtector),
}

#[enum_dispatch]
pub trait AbstractProtector {
    fn protect(&self, socket: SockRef, stack: Stack, proto: Proto) -> Result<()>;
}

impl Protector {
    // Caller should handle timeout
    pub async fn new_tcp(
        &self,
        remote: SocketAddr,
        timeout: Option<Duration>,
    ) -> Result<TcpStream> {
        let stack = match remote {
            SocketAddr::V4(_) => Stack::V4,
            SocketAddr::V6(_) => Stack::V6,
        };
        let socket = self.new_tcp_socket(stack).await?;
        let fut = socket.connect(remote);
        let stream = match timeout {
            Some(timeout) => tokio::time::timeout(timeout, fut).await??,
            None => fut.await?,
        };
        Ok(stream)
    }

    pub async fn new_tcp_socket(&self, stack: Stack) -> Result<TcpSocket> {
        let socket = socket2::Socket::new(
            match stack {
                Stack::V4 => socket2::Domain::IPV4,
                Stack::V6 => socket2::Domain::IPV6,
            },
            socket2::Type::STREAM,
            Some(Protocol::TCP),
        )?;

        self.protect(SockRef::from(&socket), stack, Proto::TCP)?;
        socket.set_keepalive(true)?;
        socket.set_nodelay(true)?;
        socket.set_nonblocking(true)?;
        #[cfg(windows)]
        let socket = {
            use std::os::windows::io::{FromRawSocket, IntoRawSocket};

            let raw_socket = socket.into_raw_socket();
            unsafe { TcpSocket::from_raw_socket(raw_socket) }
        };
        #[cfg(unix)]
        let socket = {
            use std::os::unix::io::{FromRawFd, IntoRawFd};

            let raw_fd = std_stream.into_raw_fd();
            unsafe { TcpSocket::from_raw_fd(raw_fd) }
        };
        Ok(socket)
    }

    pub async fn new_udp(&self, remote: SocketAddr) -> Result<UdpSocket> {
        let stack = match &remote {
            SocketAddr::V4(_) => Stack::V4,
            SocketAddr::V6(_) => Stack::V6,
        };
        let socket = self.new_udp_socket(stack).await?;
        socket.connect(remote).await?;
        Ok(socket)
    }

    pub async fn new_udp_socket(&self, stack: Stack) -> Result<UdpSocket> {
        let socket = socket2::Socket::new(
            match stack {
                Stack::V4 => socket2::Domain::IPV4,
                Stack::V6 => socket2::Domain::IPV6,
            },
            socket2::Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        self.protect(SockRef::from(&socket), stack, Proto::UDP)?;
        socket.set_broadcast(true)?;
        socket.set_nonblocking(true)?;
        let socket = std::net::UdpSocket::from(socket);
        Ok(socket.try_into()?)
    }
}

/// TODO move to watfaq_utils::net
pub fn apply_tcp_options<'a, T: Into<SockRef<'a>>>(s: T) -> io::Result<()> {
    let socket = s.into();
    #[cfg(not(target_os = "windows"))]
    {
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )?;
    }
    #[cfg(target_os = "windows")]
    {
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        )?;
    }
    Ok(())
}
