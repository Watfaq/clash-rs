use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::{
    app::dns::ThreadSafeDNSResolver,
    proxy::{AnyOutboundHandler, AnyStream},
};

use super::{new_tcp_stream, new_udp_socket, Interface};

/// allows a proxy to get a connection to a remote server
#[async_trait]
pub trait RemoteConnector: Send + Sync {
    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&Interface>,
        #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyStream>;

    async fn connect_datagram(
        &self,
        src: Option<&SocketAddr>,
        iface: Option<&Interface>,
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
impl RemoteConnector for DirectConnector {
    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&Interface>,
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
        &self,
        src: Option<&SocketAddr>,
        iface: Option<&Interface>,
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

pub struct ProxyConnector {
    proxy: AnyOutboundHandler,
    connector: Box<dyn RemoteConnector>,
}

impl ProxyConnector {
    pub fn new(proxy: AnyOutboundHandler, connector: Box<dyn RemoteConnector>) -> Self {
        Self { proxy, connector }
    }
}

#[async_trait]
impl RemoteConnector for ProxyConnector {
    async fn connect_stream(
        &self,
        resolver: ThreadSafeDNSResolver,
        address: &str,
        port: u16,
        iface: Option<&Interface>,
        #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
        self.connector
            .connect_stream(
                resolver,
                &address.to_owned(),
                port,
                iface,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                packet_mark,
            )
            .await
    }

    async fn connect_datagram(
        &self,
        src: Option<&SocketAddr>,
        iface: Option<&Interface>,
        #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    ) -> std::io::Result<UdpSocket> {
        self.connector
            .connect_datagram(
                src,
                iface,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                packet_mark,
            )
            .await
    }
}
