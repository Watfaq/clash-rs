use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::{
    app::dns::ThreadSafeDNSResolver,
    proxy::{AnyOutboundHandler, AnyStream},
};

use super::{new_tcp_stream, new_udp_socket, Interface};

#[async_trait]
pub trait RemoteConnector<'a> {
    async fn connect_stream(
        &'a self,
        resolver: ThreadSafeDNSResolver,
        address: &'a str,
        port: u16,
        iface: Option<&'a Interface>,
        #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyStream>;

    async fn connect_datagram(
        &'a self,
        src: Option<&SocketAddr>,
        iface: Option<&'a Interface>,
        #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    ) -> std::io::Result<UdpSocket>;
}

pub struct DirectConnector;

impl DirectConnector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl<'a> RemoteConnector<'a> for DirectConnector {
    async fn connect_stream(
        &'a self,
        resolver: ThreadSafeDNSResolver,
        address: &'a str,
        port: u16,
        iface: Option<&'a Interface>,
        #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
        new_tcp_stream(
            resolver,
            address,
            port,
            iface,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            packet_mark,
        )
        .await
    }

    async fn connect_datagram(
        &'a self,
        src: Option<&SocketAddr>,
        iface: Option<&'a Interface>,
        #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    ) -> std::io::Result<UdpSocket> {
        new_udp_socket(
            src,
            iface,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            packet_mark,
        )
        .await
    }
}

pub struct ProxyConnector<'a> {
    proxy: AnyOutboundHandler,
    connector: Box<dyn RemoteConnector<'a>>,
}

impl ProxyConnector<'_> {
    pub fn new<'a>(proxy: AnyOutboundHandler, connector: Box<dyn RemoteConnector<'a>>) -> Self {
        Self { proxy, connector }
    }
}
