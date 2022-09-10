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

impl Handler {
    async fn handle(
        &self,
        sess: Session,
        mut stream: Option<Box<dyn ProxyStream>>,
        mut dgram: Option<Box<dyn OutboundDatagram>>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        for h in self.inner_handlers.iter() {
            let mut new_sess = sess.clone();
            new_sess.destination = match h.stream()?.connect_addr() {
                OutboundConnect::Proxy(network, addr, port) => (addr, port).try_into()?,
                OutboundConnect::None => new_sess.destination,
            };
        }
    }
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
        match transport {
            Some(tr) => match tr {
                OutboundTransport::Datagram(dgram) => self.handle(sess),
            },
        }
    }
}
