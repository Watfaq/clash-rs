use std::sync::atomic::AtomicBool;

use async_trait::async_trait;
use hickory_resolver::TokioResolver;

use rand::seq::IteratorRandom;
use snafu::ResultExt;

use crate::{
    app::dns::{ClashResolver, ResolverKind},
    error::dns::{ResolveSnafu, UnsupportedSnafu},
};

pub struct SystemResolver {
    inner: TokioResolver,
    ipv6: AtomicBool,
}

/// Bug in libc, use tokio impl instead: https://sourceware.org/bugzilla/show_bug.cgi?id=10652
impl SystemResolver {
    pub fn new(ipv6: bool) -> crate::error::DnsResult<Self> {
        Ok(Self {
            inner: TokioResolver::tokio_from_system_conf().context(ResolveSnafu)?,
            ipv6: AtomicBool::new(ipv6),
        })
    }
}

#[async_trait]
impl ClashResolver for SystemResolver {
    async fn resolve(
        &self,
        host: &str,
        _: bool,
    ) -> crate::error::DnsResult<Option<std::net::IpAddr>> {
        let response = self.inner.lookup_ip(host).await.context(ResolveSnafu)?;
        Ok(response
            .iter()
            .filter(|x| self.ipv6() || x.is_ipv4())
            .choose(&mut rand::rng()))
    }

    async fn resolve_v4(
        &self,
        host: &str,
        _: bool,
    ) -> crate::error::DnsResult<Option<std::net::Ipv4Addr>> {
        let response = self.inner.ipv4_lookup(host).await.context(ResolveSnafu)?;
        Ok(response.iter().map(|x| x.0).choose(&mut rand::rng()))
    }

    async fn resolve_v6(
        &self,
        host: &str,
        _: bool,
    ) -> crate::error::DnsResult<Option<std::net::Ipv6Addr>> {
        let response = self.inner.ipv6_lookup(host).await.context(ResolveSnafu)?;
        Ok(response.iter().map(|x| x.0).choose(&mut rand::rng()))
    }

    async fn cached_for(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }

    async fn exchange(
        &self,
        _: &hickory_proto::op::Message,
    ) -> crate::error::DnsResult<hickory_proto::op::Message> {
        UnsupportedSnafu.fail()
    }

    fn ipv6(&self) -> bool {
        self.ipv6.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_ipv6(&self, val: bool) {
        self.ipv6.store(val, std::sync::atomic::Ordering::Relaxed);
    }

    fn kind(&self) -> ResolverKind {
        ResolverKind::System
    }

    fn fake_ip_enabled(&self) -> bool {
        false
    }

    async fn is_fake_ip(&self, _: std::net::IpAddr) -> bool {
        false
    }

    async fn reverse_lookup(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use hickory_resolver::TokioResolver;

    use crate::app::dns::{ClashResolver, SystemResolver};

    #[tokio::test]
    async fn test_system_resolver_with_bad_labels() {
        let resolver = TokioResolver::tokio_from_system_conf().unwrap();
        let response = resolver.lookup_ip("some_under_store.com").await;
        assert!(response.is_err());
        assert_eq!(
            response.unwrap_err().to_string(),
            "proto error: Label contains invalid characters: Err(Errors)"
        );
    }

    #[tokio::test]
    async fn test_system_resolver_default_config() {
        let resolver = SystemResolver::new(false).unwrap();
        let response = resolver.resolve("www.google.com", false).await.unwrap();
        assert!(response.is_some());
    }
}
