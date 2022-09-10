pub struct Handler;

use crate::proxy::{
    AnyOutboundDatagram, AnyStream, DatagramTransportType, OutboundConnect,
    OutboundDatagramHandler, OutboundTransport,
};
use crate::session::Session;
use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::None
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<AnyStream, AnyOutboundDatagram>>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        Err(io::Error::new(io::ErrorKind::Other, "REJECT"))
    }
}
