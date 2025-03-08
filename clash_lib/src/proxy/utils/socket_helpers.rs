#[cfg(not(target_os = "android"))]
use super::platform::must_bind_socket_on_interface;
use crate::app::net::Interface;
use socket2::TcpKeepalive;
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};
#[cfg(not(target_os = "android"))]
use tracing::{debug, error};

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
