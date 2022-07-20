use std::io;

use async_trait::async_trait;

use crate::{
    proxy::{AnyStream, OutboundConnect, OutboundStreamHandler},
    session::Session,
    Error,
};

pub struct Handler;

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Direct
    }

    async fn handle<'a>(&'a self, _sess: &'a Session, stream: AnyStream) -> io::Result<AnyStream> {
        Ok(stream)
    }
}
