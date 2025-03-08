#![feature(let_chains)]
use dns::{
    dhcp::DhcpClient,
    dns_client::EnhancedDnsClient,
    resolver::{DummyResolver, EnhancedResolver, SystemResolver},
};
use enum_dispatch::enum_dispatch;
use hickory_proto::op;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
    sync::Arc,
};
use watfaq_error::Result;
use watfaq_state::Context;
use watfaq_types::StackPrefer;

pub use self::dns::DnsConfig;

pub mod dns;

#[enum_dispatch(AbstractResolver)]
pub enum Resolver {
    System(SystemResolver),
    Enchaned(EnhancedResolver),
    Dummy(DummyResolver),
}

#[enum_dispatch]
pub trait AbstractResolver {
    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)>;

    async fn cached_for(&self, ip: std::net::IpAddr) -> Option<String>;

    /// Used for DNS Server
    async fn exchange(&self, message: &op::Message) -> Result<op::Message>;

    /// Only used for look up fake IP
    async fn reverse_lookup(&self, ip: IpAddr) -> Option<String>;
    async fn is_fake_ip(&self, ip: IpAddr) -> bool;
    fn fake_ip_enabled(&self) -> bool;

    fn stack_prefer(&self) -> StackPrefer;
    fn set_stack_perfer(&self, prefer: StackPrefer);
    fn ctx(&self) -> Arc<Context>;
}

#[enum_dispatch(AbstractDnsClient)]
#[derive(Debug)]
pub enum DnsClientInner {
    Dhcp(DhcpClient),
    Enchaned(EnhancedDnsClient),
}

#[derive(Clone, Debug)]
pub struct DnsClient(Arc<DnsClientInner>);
impl Deref for DnsClient {
    type Target = DnsClientInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<DnsClientInner> for DnsClient {
    fn from(value: DnsClientInner) -> Self {
        Self(Arc::new(value))
    }
}
impl From<DhcpClient> for DnsClient {
    fn from(value: DhcpClient) -> Self {
        value.into()
    }
}
impl From<EnhancedDnsClient> for DnsClient {
    fn from(value: EnhancedDnsClient) -> Self {
        value.into()
    }
}

#[enum_dispatch]
pub trait AbstractDnsClient {
    /// used to identify the client for logging
    fn id(&self) -> String;
    fn ctx(&self) -> Arc<Context>;
    async fn exchange(&self, msg: &op::Message) -> Result<op::Message>;
}
