use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
    },
    config::internal::proxy::PROXY_REJECT,
    proxy::OutboundHandler,
    session::Session,
};
use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use serde::Serialize;
use std::{collections::HashMap, io};

use super::{ConnectorType, DialWithConnector, OutboundType, PlainProxyAPIResponse};

#[derive(Serialize)]
pub struct Handler {
    pub name: String,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reject").field("name", &self.name).finish()
    }
}

impl Handler {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
        }
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        PROXY_REJECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Reject
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        Err(io::Error::other("REJECT"))
    }

    async fn connect_datagram(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        Err(io::Error::other("REJECT"))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("name".to_owned(), Box::new(self.name.clone()) as _);
        m.insert("type".to_owned(), Box::new(self.proto().to_string()) as _);
        m
    }
}
