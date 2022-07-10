use std::net::SocketAddr;

use async_trait::async_trait;
use futures_core::Stream;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::session::{DatagramSource, Session, SocksAddr};

pub mod socks;

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
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
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: S,
    ) -> std::io::Result<InboundTransport<S, D>>;
}

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
