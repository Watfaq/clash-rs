use crate::proxy::{
    AnyOutboundDatagram, AnyOutboundHandler, AnyOutboundTransport, AnyStream,
    DatagramTransportType, OutboundConnect, OutboundDatagram, OutboundDatagramHandler,
    OutboundTransport, ProxyStream,
};
use crate::session::Session;
use async_trait::async_trait;
use std::io;

pub struct Handler {
    pub inner_handlers: Vec<AnyOutboundHandler>,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::None
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }
}
