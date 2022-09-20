use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;

use crate::proxy::OutboundConnect;
use crate::{
    proxy::{
        AnyOutboundDatagram, AnyOutboundTransport, DatagramTransportType, OutboundDatagramHandler,
        OutboundTransport,
    },
    session::Session,
};

pub struct Handler;

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
        _sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        if let Some(OutboundTransport::Datagram(dgram)) = transport {
            Ok(dgram)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid input"))
        }
    }
}
