use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;

use crate::proxy::OutboundConnect;
use crate::{
    proxy::{AnyStream, OutboundStreamHandler},
    session::Session,
};

pub struct Handler;

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::None
    }

    async fn handle<'a>(&'a self, _sess: &'a Session, stream: AnyStream) -> io::Result<AnyStream> {
        Ok(stream)
    }
}
