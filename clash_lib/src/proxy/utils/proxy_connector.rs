use std::{fmt::Debug, net::SocketAddr, sync::Arc};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use tracing::trace;
use watfaq_resolver::{AbstractResolver, Resolver};
use watfaq_state::Context;

use crate::{
    app::{
        dispatcher::{
            ChainedDatagram, ChainedDatagramWrapper, ChainedStream,
            ChainedStreamWrapper,
        },
        net::Interface,
    },
    common::errors::new_io_error,
    proxy::{
        AnyOutboundDatagram, AnyOutboundHandler, AnyStream,
        datagram::OutboundDatagramImpl,
    },
    session::{Network, Session, SocksAddr, Type},
};

use watfaq_error::Result;

/// allows a proxy to get a connection to a remote server
#[async_trait]
pub trait RemoteConnector: Send + Sync + Debug {
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
    async fn connect_stream(
        &self,
        address: &str,
        port: u16,
    ) -> Result<AnyStream>;

    async fn connect_datagram(
        &self,
        src: Option<SocketAddr>,
        destination: SocksAddr,
    ) -> Result<AnyOutboundDatagram>;
}

#[derive(Debug)]
pub struct DirectConnector;

impl DirectConnector {
    pub fn new() -> Self {
        Self
    }
}

pub static GLOBAL_DIRECT_CONNECTOR: Lazy<Arc<dyn RemoteConnector>> =
    Lazy::new(global_direct_connector);

fn global_direct_connector() -> Arc<dyn RemoteConnector> {
    Arc::new(DirectConnector::new())
}

#[async_trait]
impl RemoteConnector for DirectConnector {
    async fn connect_stream(
        &self,
        resolver: Arc<Resolver>,
        address: &str,
        port: u16,
    ) -> std::io::Result<AnyStream> {
        let dial_addr = resolver
            .resolve(address, false)
            .await
            .map_err(|v| new_io_error(format!("can't resolve dns: {}", v)))?
            .ok_or(new_io_error("no dns result"))?;

        new_tcp_stream(
            (dial_addr, port).into(),
            iface.cloned(),
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await
        .map(|x| Box::new(x) as _)
    }

    async fn connect_datagram(
        &self,
        resolver: Arc<Resolver>,
        src: Option<SocketAddr>,
        _destination: SocksAddr,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let dgram = new_udp_socket(
            src,
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await
        .map(|x| OutboundDatagramImpl::new(x, resolver))?;

        let dgram = ChainedDatagramWrapper::new(dgram);
        Ok(Box::new(dgram))
    }
}

pub struct ProxyConnector {
    proxy: AnyOutboundHandler,
    connector: Box<dyn RemoteConnector>,
}

impl ProxyConnector {
    pub fn new(
        proxy: AnyOutboundHandler,
        // TODO: make this Arc
        connector: Box<dyn RemoteConnector>,
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
impl RemoteConnector for ProxyConnector {
    async fn connect_stream(
        &self,
        ctx: Arc<Context>,
        resolver: Arc<Resolver>,
        address: &str,
        port: u16,
        iface: Option<&Interface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyStream> {
        let sess = Session {
            network: Network::Tcp,
            typ: Type::Ignore,
            destination: crate::session::SocksAddr::Domain(address.to_owned(), port),
            iface: iface.cloned(),
            #[cfg(target_os = "linux")]
            so_mark,
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
                ctx,
                &sess,
                resolver,
                self.connector.as_ref(),
            )
            .await?;

        let stream = ChainedStreamWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        ctx: ArcSwap<Context>,
        resolver: ThreadSafeDNSResolver,
        _src: Option<SocketAddr>,
        destination: SocksAddr,
        iface: Option<Interface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> std::io::Result<AnyOutboundDatagram> {
        let sess = Session {
            network: Network::Udp,
            typ: Type::Ignore,
            iface,
            destination: destination.clone(),
            #[cfg(target_os = "linux")]
            so_mark,
            ..Default::default()
        };
        let s = self
            .proxy
            .connect_datagram_with_connector(
                ctx,
                &sess,
                resolver,
                self.connector.as_ref(),
            )
            .await?;

        let stream = ChainedDatagramWrapper::new(s);
        stream.append_to_chain(self.proxy.name()).await;
        Ok(Box::new(stream))
    }
}
