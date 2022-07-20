// a lot of these are from: https://github.com/eycorsican/leaf/blob/master/leaf/src/proxy/mod.rs

use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use futures::Stream;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proxy::datagram::SimpleOutboundDatagram;
use crate::proxy::utils::{new_tcp_stream, new_udp_socket};
use crate::{
    app::ThreadSafeAsyncDnsClient,
    session::{DatagramSource, Network, Session, SocksAddr},
};

pub mod datagram;
pub mod direct;
pub mod http;
pub mod inbound;
pub mod outbound;
pub mod reject;
pub mod shadowsocks;
pub mod socks;
pub mod utils;

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<S> ProxyStream for S where S: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
pub type AnyStream = Box<dyn ProxyStream>;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error(transparent)]
    DatagramWarn(anyhow::Error),
    #[error(transparent)]
    DatagramFatal(anyhow::Error),
}

pub type ProxyResult<T> = std::result::Result<T, ProxyError>;

pub trait InboundDatagram: Send + Sync + Unpin {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    );

    fn into_std(self: Box<Self>) -> std::io::Result<std::net::UdpSocket>;
}
#[async_trait]
pub trait InboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read, the source where this message
    /// originated and the destination this message shall be sent to.
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)>;
}
#[async_trait]
pub trait InboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a datagram message on the socket to `dst_addr`, the `src_addr`
    /// specifies the origin of the message. On success, returns the number
    /// of bytes sent.
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> std::io::Result<usize>;

    /// Close the socket gracefully.
    async fn close(&mut self) -> std::io::Result<()>;
}

pub type AnyInboundDatagram = Box<dyn InboundDatagram>;

#[async_trait]
pub trait InboundStreamHandler<S = AnyStream, D = AnyInboundDatagram>: Send + Sync + Unpin {
    async fn handle(&self, sess: Session, stream: S) -> std::io::Result<InboundTransport<S, D>>;
}

pub type AnyInboundStreamHandler = Arc<dyn InboundStreamHandler>;

/// An inbound handler for incoming UDP connections.
#[async_trait]
pub trait InboundDatagramHandler<S = AnyStream, D = AnyInboundDatagram>:
    Send + Sync + Unpin
{
    async fn handle(&self, socket: D) -> io::Result<InboundTransport<S, D>>;
}

pub type AnyInboundDatagramHandler = Arc<dyn InboundDatagramHandler>;
pub enum BaseInboundTransport<S, D> {
    /// The reliable transport.
    Stream(S, Session),
    /// The unreliable transport.
    Datagram(D, Option<Session>),
    /// None.
    Empty,
}

pub type IncomingTransport<S, D> =
    Box<dyn Stream<Item = BaseInboundTransport<S, D>> + Send + Unpin>;
pub enum InboundTransport<S, D> {
    /// The reliable transport.
    Stream(S, Session),
    /// The unreliable transport.
    Datagram(D, Option<Session>),
    /// Incoming transports can be either reliable or unreliable.
    Incoming(IncomingTransport<S, D>),
    /// None.
    Empty,
}

pub type AnyInboundTransport = InboundTransport<AnyStream, AnyInboundDatagram>;

pub trait InboundHandler: Send + Sync + Unpin {
    fn stream(&self) -> io::Result<&AnyInboundStreamHandler>;
    fn datagram(&self) -> io::Result<&AnyInboundDatagramHandler>;
}
pub type AnyInboundHandler = Arc<dyn InboundHandler>;

#[derive(Debug, Clone)]
pub enum OutboundConnect {
    Proxy(Network, String, u16),
    Direct,
    Next,
    Unknown,
}

#[async_trait]
pub trait OutboundStreamHandler<S = AnyStream>: Send + Sync + Unpin {
    /// Returns the address which the underlying transport should
    /// communicate with.
    fn connect_addr(&self) -> OutboundConnect;

    /// Handles a session with the given stream. On success, returns a
    /// stream wraps the incoming stream.
    async fn handle<'a>(&'a self, sess: &'a Session, stream: AnyStream) -> io::Result<S>;
}

type AnyOutboundStreamHandler = Box<dyn OutboundStreamHandler>;

#[async_trait]
pub trait OutboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a message on the socket. On success, returns the number of
    /// bytes read and the origin of the message.
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)>;
}

#[async_trait]
pub trait OutboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a message on the socket to `dst_addr`. On success, returns the
    /// number of bytes sent.
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize>;

    /// Close the soccket gracefully.
    async fn close(&mut self) -> io::Result<()>;
}

pub trait OutboundDatagram: Send + Unpin {
    /// Splits the datagram.
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    );
}

pub type AnyOutboundDatagram = Box<dyn OutboundDatagram>;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DatagramTransportType {
    Reliable,
    Unreliable,
    Unknown,
}

pub enum OutboundTransport<S, D> {
    /// The reliable transport.
    Stream(S),
    /// The unreliable transport.
    Datagram(D),
}

pub type AnyOutboundTransport = OutboundTransport<AnyStream, AnyOutboundDatagram>;

#[async_trait]
pub trait OutboundDatagramHandler<S = AnyStream, D = AnyOutboundDatagram>:
    Send + Sync + Unpin
{
    /// Returns the address which the underlying transport should
    /// communicate with.
    fn connect_addr(&self) -> OutboundConnect;

    /// Returns the transport type of this handler.
    fn transport_type(&self) -> DatagramTransportType;

    /// Handles a session with the transport. On success, returns an outbound
    /// datagram wraps the incoming transport.
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<S, D>>,
    ) -> io::Result<D>;
}

type AnyOutboundDatagramHandler = Box<dyn OutboundDatagramHandler>;

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin {
    fn stream(&self) -> io::Result<&AnyOutboundStreamHandler>;
    fn datagram(&self) -> io::Result<&AnyOutboundDatagramHandler>;

    async fn handle_tcp(
        &self,
        sess: &Session,
        dns_resolver: ThreadSafeAsyncDnsClient,
    ) -> io::Result<AnyStream> {
        let s = self.connect_stream(&sess, dns_resolver).await?;
        let h = match sess.network {
            Network::Tcp => self.stream()?,
            Network::Udp => self.datagram()?,
        };
        h.handle(&sess)
    }

    async fn handle_udp(
        &self,
        sess: &Session,
        dns_resolver: ThreadSafeAsyncDnsClient,
    ) -> io::Result<AnyOutboundDatagram> {
        let transport = self.connect_datagram(&sess, dns_resolver).await?;
        self.datagram()?.handle(&sess, Some(transport))
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        dns_client: ThreadSafeAsyncDnsClient,
    ) -> io::Result<AnyStream> {
        match self.stream()?.connect_addr() {
            OutboundConnect::Direct => Ok(new_tcp_stream(
                dns_client,
                &sess.destination.host(),
                sess.destination.port(),
                sess.iface,
                sess.packet_mark,
            )
            .await?),
            OutboundConnect::Proxy(Network::Tcp, addr, port) => {
                Ok(new_tcp_stream(dns_client, &addr, port, sess.iface, sess.packet_mark).await?)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                "invalid outbound connect",
            )),
        }
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        dns_resolver: ThreadSafeAsyncDnsClient,
    ) -> io::Result<AnyOutboundTransport> {
        match self.datagram()?.connect_addr() {
            OutboundConnect::Proxy(network, addr, port) => match network {
                Network::Udp => {
                    let socket = new_udp_socket(&sess.source, sess.iface, sess.packet_mark).await?;
                    Ok(OutboundTransport::Datagram(Box::new(
                        SimpleOutboundDatagram::new(socket, None, dns_resolver.clone()),
                    )))
                }
                Network::Tcp => {
                    let stream = new_tcp_stream(
                        dns_resolver.clone(),
                        addr.as_str(),
                        port,
                        sess.iface,
                        sess.packet_mark,
                    )
                    .await?;
                    Ok(OutboundTransport::Stream(stream))
                }
            },
            OutboundConnect::Direct => {
                let socket = new_udp_socket(&sess.source, sess.iface, sess.packet_mark).await?;
                let dest = match &sess.destination {
                    SocksAddr::Domain(host, port) => SocksAddr::Domain(host.into(), port.into()),
                    _ => None,
                };
                Ok(OutboundTransport::Datagram(Box::new(
                    SimpleOutboundDatagram::new(socket, dest.into(), dns_resolver.clone()),
                )))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                "invalid outbound connect",
            )),
        }
    }
}
pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;
