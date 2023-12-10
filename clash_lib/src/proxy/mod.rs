use crate::app::dispatcher::{BoxedChainedDatagram, BoxedChainedStream};
use crate::app::dns::ThreadSafeDNSResolver;
use crate::proxy::datagram::UdpPacket;
use crate::proxy::utils::Interface;
use crate::session::{Session, SocksAddr};
use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::{Sink, Stream};
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::fmt::Debug;
use std::io;
use std::sync::Arc;

use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

pub mod direct;
pub mod reject;

pub mod http;
pub mod mixed;

pub(crate) mod datagram;
mod options;

#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;
pub mod socks;
pub mod trojan;
pub mod tun;
pub mod utils;
pub mod vmess;
pub mod wg;

pub mod converters;

pub mod fallback;
pub mod loadbalance;
pub mod relay;
pub mod selector;
pub mod urltest;

mod transport;

#[cfg(test)]
pub mod mocks;

#[macro_export]
macro_rules! p_debug {
    ($($arg:tt)*) => {
        debug!(target: "proxy", $($arg)*)
    };
}

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
impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + Debug {}
pub type AnyStream = Box<dyn ProxyStream>;

pub trait InboundDatagram<Item>:
    Stream<Item = Item> + Sink<Item, Error = io::Error> + Send + Sync + Unpin + Debug
{
}
pub type AnyInboundDatagram =
    Box<dyn InboundDatagram<UdpPacket, Error = io::Error, Item = UdpPacket>>;

pub trait OutboundDatagram<Item>:
    Stream<Item = Item> + Sink<Item, Error = io::Error> + Send + Sync + Unpin
{
}

impl<T, U> OutboundDatagram<U> for T where
    T: Stream<Item = U> + Sink<U, Error = io::Error> + Send + Sync + Unpin
{
}

pub type AnyOutboundDatagram =
    Box<dyn OutboundDatagram<UdpPacket, Item = UdpPacket, Error = io::Error>>;

#[derive(Default, Debug, Clone)]
pub struct CommonOption {
    #[allow(dead_code)]
    so_mark: Option<u32>,
    iface: Option<Interface>,
}

#[async_trait]
pub trait InboundListener: Send + Sync + Unpin {
    /// support tcp or not
    fn handle_tcp(&self) -> bool;
    /// support udp or not
    fn handle_udp(&self) -> bool;
    async fn listen_tcp(&self) -> io::Result<()>;
    async fn listen_udp(&self) -> io::Result<()>;
}

pub type AnyInboundListener = Arc<dyn InboundListener>;

#[derive(Serialize, Deserialize)]
pub enum OutboundType {
    Shadowsocks,
    Vmess,
    Trojan,
    WireGuard,

    #[serde(rename = "URLTest")]
    UrlTest,
    Selector,
    Relay,
    LoadBalance,
    Fallback,

    Direct,
    Reject,
}

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin {
    /// The name of the outbound handler
    fn name(&self) -> &str;

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType;

    /// The proxy remote address
    async fn remote_addr(&self) -> Option<SocksAddr>;

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool;

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream>;

    /// wraps a stream with outbound handler
    async fn proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream>;

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram>;

    /// for API
    /// the map only contains basic information
    /// to populate history/liveness information, use the proxy_manager
    async fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("type".to_string(), Box::new(self.proto()) as _);

        m
    }
}
pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;
