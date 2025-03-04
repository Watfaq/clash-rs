#![feature(let_chains)]
use dns::{
    dhcp::DhcpClient,
    dns_client::EnhancedDnsClient,
    resolver::{DummyResolver, EnhancedResolver, SystemResolver},
};
use enum_dispatch::enum_dispatch;
use hickory_proto::op;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use watfaq_error::Result;
use watfaq_state::Context;
use watfaq_types::StackPrefer;

pub(crate) mod dns;

#[enum_dispatch(AbstractResolver)]
pub enum Resolver {
    System(SystemResolver),
    Enchaned(EnhancedResolver),
    Dummy(DummyResolver)
}

#[enum_dispatch]
pub trait AbstractResolver {
    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)>;
    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> Result<Option<Ipv4Addr>>;
    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> Result<Option<Ipv6Addr>>;
    async fn cached_for(&self, ip: std::net::IpAddr) -> Option<String>;

    /// Used for DNS Server
    async fn exchange(&self, message: &op::Message) -> Result<op::Message>;

    /// Only used for look up fake IP
    async fn reverse_lookup(&self, ip: std::net::IpAddr) -> Option<String>;
    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool;
    fn fake_ip_enabled(&self) -> bool;

    fn stack_prefer(&self) -> StackPrefer;
}

#[enum_dispatch(AbstractDnsClient)]
pub enum DnsClient {
    Dhcp(DhcpClient),
    Enchaned(EnhancedDnsClient),
}

#[enum_dispatch]
pub trait AbstractDnsClient {
    /// used to identify the client for logging
    fn id(&self) -> String;
    async fn exchange(
        &self,
        ctx: Arc<Context>,
        msg: &op::Message,
    ) -> Result<op::Message>;
}
