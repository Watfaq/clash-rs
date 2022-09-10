use crate::proxy::{AnyStream, OutboundConnect, OutboundStreamHandler};
use crate::session::Session;
use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;

pub struct Handler;

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }
}
