use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
    },
    proxy::datagram::UdpPacket,
    session::Session,
};
use async_trait::async_trait;
use downcast_rs::{Downcast, impl_downcast};
use futures::{Sink, Stream};
use serde::{Deserialize, Serialize};
use tracing::error;

use std::{
    fmt::{Debug, Display},
    io,
    sync::Arc,
};

use tokio::io::{AsyncRead, AsyncWrite};

use self::utils::RemoteConnector;

pub mod direct;
pub mod reject;

pub mod http;
pub mod mixed;
#[cfg(target_os = "linux")]
pub mod tproxy;

pub(crate) mod datagram;

pub mod converters;
pub mod hysteria2;
#[cfg(feature = "shadowquic")]
pub mod shadowquic;
#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;
pub mod socks;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "onion")]
pub mod tor;
pub mod trojan;
#[cfg(feature = "tuic")]
pub mod tuic;
pub mod tun;
pub mod utils;
pub mod vmess;
#[cfg(feature = "wireguard")]
pub mod wg;

pub mod group;
pub use group::{fallback, loadbalance, relay, selector, urltest};

mod common;
pub mod inbound;
mod options;
mod transport;
pub mod tunnel;

use crate::proxy::group::GroupProxyAPIResponse;
pub use options::HandlerCommonOptions;

#[cfg(test)]
pub mod mocks;

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("proxy error: {0}")]
    General(String),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[allow(dead_code)]
    #[error("socks5 error: {0}")]
    Socks5(String),
}

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + Debug {}
impl<T> ProxyStream for T where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + Debug
{
}
pub type AnyStream = Box<dyn ProxyStream>;

pub trait ClientStream: Downcast + AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> ClientStream for T where T: Downcast + AsyncRead + AsyncWrite + Send + Unpin {}
impl_downcast!(ClientStream);

pub trait InboundDatagram<Item>:
    Stream<Item = Item> + Sink<Item, Error = io::Error> + Send + Sync + Unpin + Debug
{
}
impl<T, U> InboundDatagram<U> for T where
    T: Stream<Item = U> + Sink<U, Error = io::Error> + Send + Sync + Unpin + Debug
{
}
pub type AnyInboundDatagram =
    Box<dyn InboundDatagram<UdpPacket, Error = io::Error, Item = UdpPacket>>;

pub trait OutboundDatagram<Item>:
    Stream<Item = Item> + Sink<Item, Error = io::Error> + Send + Sync + Unpin + 'static
{
}

impl<T, U> OutboundDatagram<U> for T where
    T: Stream<Item = U> + Sink<U, Error = io::Error> + Send + Sync + Unpin + 'static
{
}

pub type AnyOutboundDatagram =
    Box<dyn OutboundDatagram<UdpPacket, Item = UdpPacket, Error = io::Error>>;

#[derive(Serialize, Deserialize)]
pub enum OutboundType {
    Shadowsocks,
    Vmess,
    Trojan,
    WireGuard,
    Tor,
    Tuic,
    Socks5,
    Hysteria2,
    Ssh,
    ShadowQuic,

    #[serde(rename = "URLTest")]
    UrlTest,
    Selector,
    Relay,
    LoadBalance,
    Smart,
    Fallback,

    Direct,
    Reject,
}

impl Display for OutboundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundType::Shadowsocks => write!(f, "Shadowsocks"),
            OutboundType::Vmess => write!(f, "Vmess"),
            OutboundType::Trojan => write!(f, "Trojan"),
            OutboundType::WireGuard => write!(f, "WireGuard"),
            OutboundType::Tor => write!(f, "Tor"),
            OutboundType::Tuic => write!(f, "Tuic"),
            OutboundType::Socks5 => write!(f, "Socks5"),
            OutboundType::Hysteria2 => write!(f, "Hysteria2"),
            OutboundType::Ssh => write!(f, "ssh"),
            OutboundType::ShadowQuic => write!(f, "ShadowQuic"),

            OutboundType::UrlTest => write!(f, "URLTest"),
            OutboundType::Selector => write!(f, "Selector"),
            OutboundType::Relay => write!(f, "Relay"),
            OutboundType::LoadBalance => write!(f, "LoadBalance"),
            OutboundType::Smart => write!(f, "Smart"),
            OutboundType::Fallback => write!(f, "Fallback"),

            OutboundType::Direct => write!(f, "Direct"),
            OutboundType::Reject => write!(f, "Reject"),
        }
    }
}

pub enum ConnectorType {
    Tcp,
    All,
    None,
}

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin + DialWithConnector + Debug {
    /// The name of the outbound handler
    fn name(&self) -> &str;

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType;

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool;

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream>;

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram>;

    /// relay related
    async fn support_connector(&self) -> ConnectorType;

    async fn connect_stream_with_connector(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        error!("tcp relay not supported for {}", self.proto());
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("tcp relay not supported for {}", self.proto()),
        ))
    }

    async fn connect_datagram_with_connector(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedDatagram> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("udp relay not supported for {}", self.proto()),
        ))
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        None
    }
}
pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;

#[async_trait]
pub trait DialWithConnector {
    fn support_dialer(&self) -> Option<&str> {
        None
    }

    /// register a dialer for the outbound handler
    /// this must be called before the outbound handler is used
    async fn register_connector(&self, _: Arc<dyn RemoteConnector>) {}
}
