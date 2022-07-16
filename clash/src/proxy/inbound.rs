use crate::proxy::{AnyInboundDatagramHandler, AnyInboundStreamHandler, InboundHandler};
use std::io;

pub struct Handler {
    name: String,
    stream_handler: Option<AnyInboundStreamHandler>,
    datagram_handler: Option<AnyInboundDatagramHandler>,
}

impl Handler {
    pub fn new(
        name: &str,
        stream: Option<AnyInboundStreamHandler>,
        datagram: Option<AnyInboundDatagramHandler>,
    ) -> Self {
        Self {
            name: name.into(),
            stream_handler: stream,
            datagram_handler: datagram,
        }
    }
}

impl InboundHandler for Handler {
    fn stream(&self) -> std::io::Result<&AnyInboundStreamHandler> {
        self.stream_handler
            .as_ref()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no tcp handler"))
    }

    fn datagram(&self) -> std::io::Result<&AnyInboundDatagramHandler> {
        self.datagram_handler
            .as_ref()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no udp handler"))
    }
}
