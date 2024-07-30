use async_trait::async_trait;

use std::fmt::Debug;

use hickory_proto::op;
use std::sync::Arc;

#[cfg(test)]
use mockall::automock;

mod config;
mod dhcp;
mod dns_client;
mod dummy_keys;
mod fakeip;
mod filters;
mod helper;
pub mod resolver;
mod server;

pub use config::Config;

pub use resolver::{new as new_resolver, EnhancedResolver, SystemResolver};

pub use server::get_dns_listener;

#[async_trait]
pub trait Client: Sync + Send + Debug {
    /// used to identify the client for logging
    fn id(&self) -> String;
    async fn exchange(&self, msg: &op::Message) -> anyhow::Result<op::Message>;
}

type ThreadSafeDNSClient = Arc<dyn Client>;

pub enum ResolverKind {
    Clash,
    System,
}

pub type ThreadSafeDNSResolver = Arc<dyn ClashResolver>;

/// A implementation of "anti-poisoning" Resolver
/// it can hold multiple clients in different protocols
/// each client can also hold a "default_resolver"
/// in case they need to resolve DoH in domain names etc.  
#[cfg_attr(test, automock)]
#[async_trait]
pub trait ClashResolver: Sync + Send {
    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>>;
    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>>;
    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>>;

    async fn exchange(&self, message: op::Message) -> anyhow::Result<op::Message>;

    /// Only used for look up fake IP
    async fn reverse_lookup(&self, ip: std::net::IpAddr) -> Option<String>;
    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool;
    async fn fake_ip_exists(&self, ip: std::net::IpAddr) -> bool;

    fn ipv6(&self) -> bool;
    fn set_ipv6(&self, enable: bool);

    fn kind(&self) -> ResolverKind;

    fn fake_ip_enabled(&self) -> bool;
}
