use async_trait::async_trait;
use hickory_resolver::{
    name_server::{GenericConnector, TokioRuntimeProvider},
    AsyncResolver,
};
use rand::seq::IteratorRandom;
use tracing::warn;

use super::{ClashResolver, ResolverKind};

pub struct SystemResolver(AsyncResolver<GenericConnector<TokioRuntimeProvider>>);

/// SystemResolver is a resolver that uses libc getaddrinfo to resolve
/// hostnames.
impl SystemResolver {
    pub fn new() -> anyhow::Result<Self> {
        warn!(
            "Default dns resolver doesn't support ipv6, please enable clash dns \
             resolver if you need ipv6 support."
        );

        let resolver: AsyncResolver<
            GenericConnector<hickory_resolver::name_server::TokioRuntimeProvider>,
        > = hickory_resolver::AsyncResolver::tokio_from_system_conf()?;

        Ok(Self(resolver))
    }
}

#[async_trait]
impl ClashResolver for SystemResolver {
    async fn resolve(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        let response = self.0.lookup_ip(host).await?;
        Ok(response
            .iter()
            .filter(|x| self.ipv6() || x.is_ipv4())
            .choose(&mut rand::thread_rng()))
    }

    async fn resolve_v4(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
        let response = self.0.ipv4_lookup(host).await?;
        Ok(response.iter().map(|x| x.0).choose(&mut rand::thread_rng()))
    }

    async fn resolve_v6(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
        let response = self.0.ipv6_lookup(host).await?;
        Ok(response.iter().map(|x| x.0).choose(&mut rand::thread_rng()))
    }

    async fn exchange(
        &self,
        _: hickory_proto::op::Message,
    ) -> anyhow::Result<hickory_proto::op::Message> {
        Err(anyhow::anyhow!("unsupported"))
    }

    fn ipv6(&self) -> bool {
        // TODO: support ipv6
        false
    }

    fn set_ipv6(&self, _: bool) {
        // NOOP
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

    async fn fake_ip_exists(&self, _: std::net::IpAddr) -> bool {
        false
    }

    async fn reverse_lookup(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use hickory_resolver::TokioAsyncResolver;

    use crate::app::dns::{ClashResolver, SystemResolver};

    #[tokio::test]
    async fn test_system_resolver_with_bad_labels() {
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
        let response = resolver.lookup_ip("some_under_store.com").await;
        assert!(response.is_err());
        assert_eq!(
            response.unwrap_err().to_string(),
            "proto error: Label contains invalid characters: Err(Errors { \
             invalid_mapping, disallowed_by_std3_ascii_rules })"
        );
    }

    #[tokio::test]
    async fn test_system_resolver_default_config() {
        let resolver = SystemResolver::new().unwrap();
        let response = resolver.resolve("www.google.com", false).await.unwrap();
        assert!(response.is_some());
    }
}
