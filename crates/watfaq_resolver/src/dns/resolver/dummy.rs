use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use watfaq_error::{Result, anyhow};
use watfaq_state::Context;
use watfaq_types::StackPrefer;

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

    fn ctx(&self) -> Arc<Context> {
        todo!()
    }

    fn set_stack_perfer(&self, prefer: StackPrefer) {
        todo!()
    }
}
