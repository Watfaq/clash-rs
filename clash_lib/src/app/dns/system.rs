use async_trait::async_trait;
use rand::seq::IteratorRandom;
use trust_dns_resolver::{Name, TokioAsyncResolver};

use super::{ClashResolver, ResolverKind};

pub struct SystemResolver {
    resolver: TokioAsyncResolver,
}

impl SystemResolver {
    pub fn new() -> anyhow::Result<Self> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
        Ok(Self { resolver })
    }
}

#[async_trait]
impl ClashResolver for SystemResolver {
    async fn resolve(&self, host: &str, _: bool) -> anyhow::Result<Option<std::net::IpAddr>> {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(Some(ip));
        }

        let host = Name::from_str_relaxed(host)?;
        let response = self.resolver.lookup_ip(host).await?;
        Ok(response.iter().choose(&mut rand::thread_rng()))
    }

    async fn resolve_v4(&self, host: &str, _: bool) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
        let host = Name::from_str_relaxed(host)?;
        let response = self.resolver.lookup_ip(host).await?;
        Ok(response
            .iter()
            .filter_map(|ip| match ip {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .choose(&mut rand::thread_rng()))
    }
    async fn resolve_v6(&self, host: &str, _: bool) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
        let host = Name::from_str_relaxed(host)?;
        let response = self.resolver.lookup_ip(host).await?;
        Ok(response
            .iter()
            .filter_map(|ip| match ip {
                std::net::IpAddr::V6(ip) => Some(ip),
                _ => None,
            })
            .choose(&mut rand::thread_rng()))
    }

    fn ipv6(&self) -> bool {
        true
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
    use trust_dns_resolver::TokioAsyncResolver;

    #[tokio::test]
    async fn test_system_resolver_with_bad_labels() {
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
        let response = resolver.lookup_ip("some_under_store.com").await;
        assert!(response.is_err());
        assert_eq!(
            response.unwrap_err().to_string(),
            "proto error: Label contains invalid characters: Err(Errors { invalid_mapping, disallowed_by_std3_ascii_rules })"
        );
    }
}
