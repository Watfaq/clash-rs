use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use watfaq_error::anyhow;
use watfaq_types::StackPrefer;
use watfaq_error::Result;

use crate::AbstractResolver;



pub struct DummyResolver;

impl AbstractResolver for DummyResolver {
    async fn resolve(
        &self,
        host: &str,
        _: bool,
    ) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        let addr = host.parse::<IpAddr>()?;
        Ok(match addr {
            IpAddr::V4(v4) => (Some(v4), None),
            IpAddr::V6(v6) => (None, Some(v6)),
        })
    }

    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> Result<Option<Ipv4Addr>> {
        Ok(self.resolve(host, enhanced).await?.0)
    }

    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> Result<Option<Ipv6Addr>> {
        Ok(self.resolve(host, enhanced).await?.1)
    }

    async fn cached_for(&self, _: IpAddr) -> Option<String> {
        None
    }

    async fn exchange(
        &self,
        _: &hickory_proto::op::Message,
    ) -> Result<hickory_proto::op::Message> {
        Err(anyhow!("unsupported"))
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
    
    fn stack_prefer(&self) -> StackPrefer {
        todo!()
    }
}
