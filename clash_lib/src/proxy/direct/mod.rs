use std::{fmt::Debug, net::SocketAddr};

use crate::{
    app::dispatcher::{
        BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
        ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
    },
    config::internal::proxy::PROXY_DIRECT,
    proxy::{AbstractOutboundHandler, datagram::OutboundDatagramImpl},
    session::Session,
};

use async_trait::async_trait;
use serde::Serialize;
use watfaq_error::Result;
use watfaq_resolver::AbstractResolver;
use watfaq_utils::which_ip_decision;

use super::{ConnectorType, OutboundDatagram, OutboundType, utils::AbstractDialer};

#[derive(Serialize)]
pub struct Handler;

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Direct").finish()
    }
}

impl Handler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AbstractOutboundHandler for Handler {
    fn name(&self) -> &str {
        PROXY_DIRECT
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Direct
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(&self, sess: &Session) -> Result<BoxedChainedStream> {
        let ip = sess.resolved_ip;
        let ip = match ip {
            Some(v) => v,
            None => {
                let remote_ip = self.resolver()
                .resolve(sess.destination.host().as_str(), false) // FIXME it's pretty wired
                .await?;
                which_ip_decision(self.ctx(), None, None, remote_ip)?
            }
        };
        let tcp_stream = self
            .ctx()
            .protector
            .new_tcp(SocketAddr::new(ip, sess.destination.port()), None)
            .await?; //TODO timeout

        let s = ChainedStreamWrapper::new(tcp_stream);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
    ) -> Result<BoxedChainedDatagram> {
        let ip = sess.resolved_ip;
        let ip = match ip {
            Some(v) => v,
            None => {
                let remote_ip = self.resolver()
                .resolve(sess.destination.host().as_str(), false) // FIXME it's pretty wired
                .await?;
                which_ip_decision(self.ctx(), None, None, remote_ip)?
            }
        };
        let udp_socket = self
            .ctx()
            .protector
            .new_udp(SocketAddr::new(ip, sess.destination.port()))
            .await?;

        let d: ChainedDatagramWrapper<OutboundDatagramImpl> =
            ChainedDatagramWrapper::new(OutboundDatagramImpl::new(
                udp_socket,
                self.clone_resolver(),
            ));
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        connector: &dyn AbstractDialer,
    ) -> Result<BoxedChainedStream> {
        let s = connector
            .connect_stream(
                sess.destination.host().as_str(),
                sess.destination.port(),
            )
            .await?;
        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        connector: &dyn AbstractDialer,
    ) -> Result<BoxedChainedDatagram> {
        let d = connector
            .connect_datagram(None, sess.destination.clone())
            .await?;
        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }
}
