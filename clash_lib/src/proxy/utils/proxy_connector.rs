use std::{fmt::Debug, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use once_cell::sync::Lazy;
use tracing::trace;
use watfaq_resolver::{AbstractResolver, Resolver};
use watfaq_state::Context;
use watfaq_types::Stack;
use watfaq_utils::which_ip_decision;

use crate::{
    app::
        dispatcher::{
            ChainedDatagram, ChainedDatagramWrapper, ChainedStream,
            ChainedStreamWrapper,
        }
    ,
    proxy::{
        AnyOutboundDatagram, AnyOutboundHandler, AnyStream,
        datagram::OutboundDatagramImpl,
    },
    session::{Network, Session, TargetAddr, Type},
};

use watfaq_error::Result;

/// allows a proxy to get a connection to a remote server
#[async_trait]
pub trait AbstractDialer: Send + Sync + Debug {
    fn ctx(&self) -> &Context {
        todo!()
    }
    fn arc_ctx(&self) -> Arc<Context> {
        todo!()
    }
    fn resolver(&self) -> &Resolver {
        todo!()
    }
    fn clone_resolver(&self) -> Arc<Resolver> {
        todo!()
    }
    // FIXME address could be socket address?
    async fn connect_stream(&self, address: &str, port: u16) -> Result<AnyStream>;

    async fn connect_datagram(
        &self,
        src: Option<SocketAddr>,
        destination: TargetAddr,
    ) -> Result<AnyOutboundDatagram>;
}

#[derive(Debug)]
pub struct DirectConnector;

impl DirectConnector {
    pub fn new() -> Self {
        Self
    }
}

pub static GLOBAL_DIRECT_CONNECTOR: Lazy<Arc<dyn AbstractDialer>> = Lazy::new(|| {
    Arc::new(DirectConnector::new())
});

#[async_trait]
impl AbstractDialer for DirectConnector {
    async fn connect_stream(
        &self,
        address: &str,
        port: u16,
    ) -> Result<AnyStream> {
        let dial_addr = self.resolver()
            .resolve(address, false)
            .await?;
        let ip = which_ip_decision(self.ctx(), None, None, dial_addr)?;
        let stream = self.ctx().protector.new_tcp(SocketAddr::new(ip, port), None).await?;

        Ok(Box::new(stream))
    }

    // TODO I think this is buggy
    async fn connect_datagram(
        &self,
        src: Option<SocketAddr>,
        destination: TargetAddr,
    ) -> Result<AnyOutboundDatagram> {
        let stack: Stack = match src {
            Some(v) => (&v).into(),
            None => todo!(),
        };
        let socket = self.ctx().protector.new_udp_socket(stack).await?;
        let dgram = OutboundDatagramImpl::new(socket, self.clone_resolver());
        let dgram = ChainedDatagramWrapper::new(dgram);
        Ok(Box::new(dgram))
    }
}

pub struct ProxyConnector {
    proxy: AnyOutboundHandler,
    connector: Box<dyn AbstractDialer>,
}

impl ProxyConnector {
    pub fn new(
        proxy: AnyOutboundHandler,
        // TODO: make this Arc
        connector: Box<dyn AbstractDialer>,
    ) -> Self {
        Self { proxy, connector }
    }
}

impl Debug for ProxyConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConnector")
            .field("proxy", &self.proxy.name())
            .finish()
    }
}

#[async_trait]
impl AbstractDialer for ProxyConnector {
    async fn connect_stream(
        &self,
        address: &str,
        port: u16,
    ) -> Result<AnyStream> {
        let sess = Session {
            network: Network::TCP,
            typ: Type::Ignore,
            destination: crate::session::TargetAddr::Domain(
                address.to_owned(),
                port,
            ),
            ..Default::default()
        };

        trace!(
            "proxy connector `{}` connecting to {}:{}",
            self.proxy.name(),
            address,
            port
        );

        let s = self
            .proxy
            .connect_stream_with_connector(
                &sess,
                self.connector.as_ref(),
            )
            .await?;

        let stream = ChainedStreamWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        _src: Option<SocketAddr>,
        destination: TargetAddr,
    ) -> Result<AnyOutboundDatagram> {
        let sess = Session {
            network: Network::UDP,
            typ: Type::Ignore,
            destination: destination.clone(),
            ..Default::default()
        };
        let s = self
            .proxy
            .connect_datagram_with_connector(
                &sess,
                self.connector.as_ref(),
            )
            .await?;

        let stream = ChainedDatagramWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }
}
