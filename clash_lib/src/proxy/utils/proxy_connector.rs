use std::net::SocketAddr;

use async_trait::async_trait;

use crate::{
    app::{
        dispatcher::{
            ChainedDatagram, ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    proxy::{datagram::OutboundDatagramImpl, AnyOutboundDatagram, AnyOutboundHandler, AnyStream},
    session::{Network, Session, Type},
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
        resolver: ThreadSafeDNSResolver,
        src: Option<&SocketAddr>,
        iface: Option<&Interface>,
        #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram>;
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
        resolver: ThreadSafeDNSResolver,
        src: Option<&SocketAddr>,
        iface: Option<&Interface>,
        #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let dgram = new_udp_socket(
            src,
            iface,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            packet_mark,
        )
        .await
        .map(|x| OutboundDatagramImpl::new(x, resolver))?;

        let dgram = ChainedDatagramWrapper::new(dgram);
        Ok(Box::new(dgram))
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
        let sess = Session {
            network: Network::Tcp,
            typ: Type::Ignore,
            destination: crate::session::SocksAddr::Domain(address.to_owned(), port),
            iface: iface.cloned(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            packet_mark,
            ..Default::default()
        };
        let s = self
            .proxy
            .connect_stream_with_connector(&sess, resolver, &self.connector)
            .await?;

        let stream = ChainedStreamWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        resolver: ThreadSafeDNSResolver,
        _src: Option<&SocketAddr>,
        iface: Option<&Interface>,
        #[cfg(any(target_os = "linux", target_os = "android"))] packet_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let sess = Session {
            network: Network::Udp,
            typ: Type::Ignore,
            iface: iface.cloned(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            packet_mark,
            ..Default::default()
        };
        let s = self
            .proxy
            .connect_datagram_with_connector(&sess, resolver, &self.connector)
            .await?;

        let stream = ChainedDatagramWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }
}
