use std::io;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::op;
use watfaq_state::Context;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::{ClashResolver, ResolverKind, ThreadSafeDNSResolver},
    },
    proxy::{ConnectorType, DialWithConnector, OutboundHandler, OutboundType},
    session::Session,
};

pub struct NoopResolver;

#[async_trait]
impl ClashResolver for NoopResolver {
    async fn resolve_old(
        &self,
        _host: &str,
        _enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        Ok(None)
    }

    async fn resolve_v4_old(
        &self,
        _host: &str,
        _enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
        Ok(None)
    }

    async fn resolve_v6_old(
        &self,
        _host: &str,
        _enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
        Ok(None)
    }

    async fn cached_for(&self, _ip: std::net::IpAddr) -> Option<String> {
        None
    }

    /// Used for DNS Server
    async fn exchange(&self, _message: &op::Message) -> anyhow::Result<op::Message> {
        Err(anyhow::anyhow!("unsupported"))
    }

    /// Only used for look up fake IP
    async fn reverse_lookup(&self, _ip: std::net::IpAddr) -> Option<String> {
        None
    }

    async fn is_fake_ip(&self, _ip: std::net::IpAddr) -> bool {
        false
    }

    fn fake_ip_enabled(&self) -> bool {
        false
    }

    fn ipv6(&self) -> bool {
        false
    }

    fn set_ipv6(&self, _enable: bool) {}

    fn kind(&self) -> ResolverKind {
        ResolverKind::Clash
    }
}

#[derive(Debug)]
pub struct NoopOutboundHandler {
    pub name: String,
}

#[async_trait]
impl DialWithConnector for NoopOutboundHandler {
    fn support_dialer(&self) -> Option<&str> {
        None
    }
}

#[async_trait]
impl OutboundHandler for NoopOutboundHandler {
    fn name(&self) -> &str {
        &self.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Direct
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        _ctx: ArcSwap<Context>,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        Err(io::Error::new(io::ErrorKind::Other, "noop"))
    }

    async fn connect_datagram(
        &self,
        _ctx: ArcSwap<Context>,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        Err(io::Error::new(io::ErrorKind::Other, "noop"))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }
}
