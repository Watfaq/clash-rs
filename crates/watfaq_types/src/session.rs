use std::net::SocketAddr;

use crate::{Proto, Stack};

pub struct Session {
    /// The network type, representing either TCP or UDP.
    pub network: Proto,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: SocketAddr,
}
