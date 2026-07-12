use std::{net::SocketAddr, sync::Arc};

use crate::{Stoppable, error::SResult, msgs::squic::ConnStats, utils::socket_opt::SocketFactory};
use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

// 4 times larger than quinn default value
// Better decrease the size for portable device
pub const MAX_WINDOW_BASE: u64 = 4 * 12_500_000 * 100 / 1000; // 100ms RTT
pub const MAX_STREAM_WINDOW: u64 = MAX_WINDOW_BASE;
pub const MAX_SEND_WINDOW: u64 = MAX_WINDOW_BASE * 8;
pub const MAX_DATAGRAM_WINDOW: u64 = MAX_WINDOW_BASE * 2;

// #[cfg(feature = "gm-quic")]
// mod gm_quic_wrapper;
// #[cfg(feature = "gm-quic")]
// pub use gm_quic_wrapper::{Connection, EndClient, EndServer, QuicErrorRepr};

#[async_trait]
pub trait QuicClient: Send + Sync {
    type C: QuicConnection;
    type SC: Clone + Send + Sync + 'static;
    async fn new(cfg: &Self::SC) -> SResult<Self>
    where
        Self: Sized;
    async fn new_with_socket_factory(
        cfg: &Self::SC,
        socket_factory: Arc<dyn SocketFactory>,
    ) -> SResult<Self>
    where
        Self: Sized;
    async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Self::C, QuicErrorRepr>;
}
#[async_trait]
pub trait QuicServer: Send + Sync {
    type C: QuicConnection;
    type SC: Clone + Send + Sync + 'static;
    async fn new(cfg: &Self::SC) -> SResult<Self>
    where
        Self: Sized;
    async fn accept(&self) -> Result<Self::C, QuicErrorRepr>;
    async fn update_config(&self, cfg: &Self::SC) -> SResult<()>;
}

#[async_trait]
pub trait QuicConnection: Send + Sync + Clone + 'static {
    type SendStream: AsyncWrite + Unpin + Send + Sync + 'static;
    type RecvStream: AsyncRead + Unpin + Send + Sync + 'static;
    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr>;
    async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream, u64), QuicErrorRepr>;
    async fn open_uni(&self) -> Result<(Self::SendStream, u64), QuicErrorRepr>;
    async fn accept_uni(&self) -> Result<(Self::RecvStream, u64), QuicErrorRepr>;
    async fn read_datagram(&self) -> Result<Bytes, QuicErrorRepr>;
    async fn send_datagram(&self, bytes: Bytes) -> Result<(), QuicErrorRepr>;
    fn close(&self, error_code: u64, reason: &[u8]);
    fn close_reason(&self) -> Option<QuicErrorRepr>;
    fn remote_address(&self) -> SocketAddr;
    fn peer_id(&self) -> u64;
    fn get_conn_stats(&self) -> Option<ConnStats> {
        None
    }
}

impl<T: QuicConnection> Stoppable for T {
    fn stop(&self) {
        self.close(0, b"stopped by user");
    }
}

pub trait AuthedConn {
    fn authed_user(&self) -> Option<String>;
}

#[derive(Error, Debug)]
#[error(transparent)]
pub enum QuicErrorRepr {
    // gm-quic errors
    #[error("QUIC IO Error:{0}")]
    QuicIoError(String),
    #[error("QUIC Error:{0}")]
    QuicBaseError(String),
    #[error("Failed to build Quic Listener:{0}")]
    QuicListenerBuilderError(String),

    // quinn errors
    #[error("QUIC Connect Error:{0}")]
    QuicConnect(String),
    #[error("QUIC Connection Error:{0}")]
    QuicConnection(String),
    #[error("QUIC Write Error:{0}")]
    QuicWrite(String),
    #[error("QUIC ReadExact Error:{0}")]
    QuicReadExactError(String),
    #[error("QUIC SendDatagramError:{0}")]
    QuicSendDatagramError(String),
    #[error("JLS Authentication failed")]
    JlsAuthFailed,
}
