use std::{io, sync::Arc};

use super::{
    AnyOutboundDatagramHandler, AnyOutboundHandler, AnyOutboundStreamHandler, OutboundHandler,
};

pub struct CommonOutboundOpt {
    pub iface: String,
    pub rmark: u16,
}

pub struct Handler {
    name: String,
    stream_handler: Option<AnyOutboundStreamHandler>,
    datagram_handler: Option<AnyOutboundDatagramHandler>,
}

impl Handler {
    fn new(
        name: &str,
        stream_handler: Option<AnyOutboundStreamHandler>,
        datagram_handler: Option<AnyOutboundDatagramHandler>,
    ) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            stream_handler,
            datagram_handler,
        })
    }
}

impl OutboundHandler for Handler {
    fn stream(&self) -> std::io::Result<&AnyOutboundStreamHandler> {
        self.stream_handler
            .as_ref()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no tcp handler"))
    }

    fn datagram(&self) -> std::io::Result<&AnyOutboundDatagramHandler> {
        self.datagram_handler
            .as_ref()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no udp handler"))
    }
}

pub struct HandlerBuilder {
    name: String,
    stream_handler: Option<AnyOutboundStreamHandler>,
    datagram_handler: Option<AnyOutboundDatagramHandler>,
}

impl HandlerBuilder {
    pub fn new() -> Self {
        Self {
            name: String::from(""),
            stream_handler: None,
            datagram_handler: None,
        }
    }
    pub fn name(mut self, v: &str) -> Self {
        self.name = String::from(v);
        self
    }
    // https://users.rust-lang.org/t/what-is-different-between-mut-self-and-mut-self/59708/2
    pub fn stream_handler(mut self, v: AnyOutboundStreamHandler) -> Self {
        self.stream_handler.replace(v);
        self
    }

    pub fn datagram_handler(mut self, v: AnyOutboundDatagramHandler) -> Self {
        self.datagram_handler.replace(v);
        self
    }

    pub fn build(self) -> AnyOutboundHandler {
        Handler::new(
            self.name.as_str(),
            self.stream_handler,
            self.datagram_handler,
        )
    }
}

impl Default for HandlerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
