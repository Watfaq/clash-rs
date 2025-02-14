pub mod dns;

pub use dns::{DnsError, DnsResult};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    StdNet(#[from] std::net::AddrParseError),
    #[error(transparent)]
    IpNet(#[from] ipnet::AddrParseError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("profile error: {0}")]
    ProfileError(String),
    #[error("dns error: {0}")]
    DNSError(String),
    #[error(transparent)]
    DNSServerError(#[from] watfaq_dns::DNSError),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("operation error: {0}")]
    Operation(String),
}