use crate::quic::QuicErrorRepr;
use std::io;
use std::result;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SError {
    #[error("Protocol Violated")]
    ProtocolViolation,
    #[error("Protocol Unimplemented")]
    ProtocolUnimpl,
    #[error("IO Error:{0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    QuicError(#[from] QuicErrorRepr),
    #[error("Rustls Error:{0}")]
    RustlsError(String),
    #[error("Outbound unavailable")]
    OutboundUnavailable,
    #[error("Inbound unavailable")]
    InboundUnavailable,
    #[error("hostname {0} can't be resolved")]
    DomainResolveFailed(String),
    #[error("mpsc channel error: {0}")]
    ChannelError(String),
    #[error("UDP session closed closed due to: {0}")]
    UDPSessionClosed(String),
    #[error("socks error: {0}")]
    SocksError(String),
    #[error("Sunnyquic authentication error: {0}")]
    SunnyAuthError(String),
}

pub type SResult<T> = result::Result<T, SError>;

// #[derive(Error, Debug)]
// #[error(transparent)]
// pub struct QuicError(#[from] QuicErrorRepr);

// impl From<rustls_jls::Error> for SError {
//     fn from(err: rustls_jls::Error) -> Self {
//         SError::RustlsError(err.to_string())
//     }
// }

impl From<quinn::rustls::Error> for SError {
    fn from(err: quinn::rustls::Error) -> Self {
        SError::RustlsError(err.to_string())
    }
}

impl From<Box<dyn std::error::Error + 'static + Send + Sync>> for SError {
    fn from(err: Box<dyn std::error::Error + 'static + Send + Sync>) -> Self {
        SError::Io(io::Error::other(err))
    }
}
