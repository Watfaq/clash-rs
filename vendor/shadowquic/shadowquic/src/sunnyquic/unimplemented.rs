//! This module provides an empty implementation of the SunnyQuic QUIC client and server.
//! It mainly serves as a placeholder when neither the `sunnyquic-noq` nor the `sunnyquic-gm-quic` feature is enabled.
//! And git rid of the dependences of `noq` or `gm-quic` crates.

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    config::SunnyQuicServerCfg,
    error::SResult,
    quic::{QuicClient, QuicConnection, QuicErrorRepr, QuicServer},
};

#[derive(Clone)]
pub struct Connection;

#[derive(Clone)]
pub struct EndClient;
#[async_trait]
impl QuicClient for EndClient {
    type SC = crate::config::SunnyQuicClientCfg;
    type C = Connection;

    async fn new(_cfg: &Self::SC) -> crate::error::SResult<Self> {
        unimplemented!()
    }

    async fn connect(
        &self,
        _addr: std::net::SocketAddr,
        _server_name: &str,
    ) -> Result<Self::C, crate::quic::QuicErrorRepr> {
        unimplemented!()
    }

    async fn new_with_socket_factory(
        _cfg: &Self::SC,
        _socket_factory: std::sync::Arc<dyn crate::utils::socket_opt::SocketFactory>,
    ) -> crate::error::SResult<Self> {
        unimplemented!()
    }
}
#[derive(Clone)]
pub struct EndServer;
pub struct SendStream;

pub struct RecvStream;

impl AsyncRead for RecvStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        unimplemented!()
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        unimplemented!()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        unimplemented!()
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        unimplemented!()
    }
}

#[async_trait]
impl QuicConnection for Connection {
    type RecvStream = RecvStream;
    type SendStream = SendStream;

    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr> {
        unimplemented!()
    }

    async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr> {
        unimplemented!()
    }

    async fn open_uni(&self) -> Result<(Self::SendStream, u64), QuicErrorRepr> {
        unimplemented!()
    }

    async fn accept_uni(&self) -> Result<(Self::RecvStream, u64), QuicErrorRepr> {
        unimplemented!()
    }

    async fn read_datagram(&self) -> Result<bytes::Bytes, QuicErrorRepr> {
        unimplemented!()
    }

    async fn send_datagram(&self, _bytes: bytes::Bytes) -> Result<(), QuicErrorRepr> {
        unimplemented!()
    }

    fn close_reason(&self) -> Option<QuicErrorRepr> {
        unimplemented!()
    }

    fn remote_address(&self) -> std::net::SocketAddr {
        unimplemented!()
    }

    fn peer_id(&self) -> u64 {
        unimplemented!()
    }
    fn close(&self, _error_code: u64, _reason: &[u8]) {
        unimplemented!()
    }
}

#[async_trait]
impl QuicServer for EndServer {
    type C = Connection;
    type SC = SunnyQuicServerCfg;

    async fn new(_cfg: &Self::SC) -> SResult<Self>
    where
        Self: Sized,
    {
        unimplemented!()
    }

    async fn accept(&self) -> Result<Self::C, QuicErrorRepr> {
        unimplemented!()
    }

    async fn update_config(&self, _cfg: &Self::SC) -> SResult<()> {
        unimplemented!()
    }
}
