use async_trait::async_trait;
use rand::seq::IteratorRandom;
use trust_dns_resolver::TokioAsyncResolver;

use super::ClashResolver;

pub(crate) struct SystemResolver {
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
    async fn resolve(&self, host: &str) -> anyhow::Result<Option<std::net::IpAddr>> {
        let response = self.resolver.lookup_ip(host).await?;
        Ok(response.iter().choose(&mut rand::thread_rng()))
    }
    async fn resolve_v4(&self, host: &str) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
        let response = self.resolver.lookup_ip(host).await?;
        Ok(response
            .iter()
            .filter_map(|ip| match ip {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .choose(&mut rand::thread_rng()))
    }
    async fn resolve_v6(&self, host: &str) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
        let response = self.resolver.lookup_ip(host).await?;
        Ok(response
            .iter()
            .filter_map(|ip| match ip {
                std::net::IpAddr::V6(ip) => Some(ip),
                _ => None,
            })
            .choose(&mut rand::thread_rng()))
    }
}
