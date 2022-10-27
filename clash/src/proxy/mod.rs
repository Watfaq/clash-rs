use crate::proxy::datagram::UdpPacket;
use crate::proxy::utils::Interface;
use crate::session::{Session, SocksAddr};
use crate::ThreadSafeDNSResolver;
use async_trait::async_trait;
use futures::{Sink, Stream};
use std::fmt::Debug;
use std::io;
use std::sync::Arc;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

pub mod direct;
pub mod reject;

pub(crate) mod datagram;
pub mod http;
#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;
pub mod socks;
pub mod utils;

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("proxy error: {0}")]
    General(String),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("socks5 error: {0}")]
    Socks5(String),
}

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
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

#[async_trait]
pub trait OutboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a message on the socket. On success, returns the number of
    /// bytes read and the origin of the message.
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)>;
}

/// The send half.
#[async_trait]
pub trait OutboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a message on the socket to `dst_addr`. On success, returns the
    /// number of bytes sent.
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize>;
}

pub struct CommonOption {
    so_mark: Option<u32>,
    iface: Option<Interface>,
}

impl Default for CommonOption {
    fn default() -> Self {
        Self {
            so_mark: None,
            iface: None,
        }
    }
}

#[async_trait]
pub trait InboundListener: Send + Sync + Unpin {
    fn handle_tcp(&self) -> bool;
    fn handle_udp(&self) -> bool;
    async fn listen_tcp(&self) -> io::Result<()>;
    async fn listen_udp(&self) -> io::Result<()>;
}

pub type AnyInboundListener = Arc<dyn InboundListener>;

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin {
    fn name(&self) -> &str;

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream>;

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram>;
}
pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;

#[async_trait]
pub trait ProxyChain: Sync + Send + Unpin {
    async fn chain(&self, s: AnyStream, sess: &Session) -> io::Result<AnyStream>;
}
