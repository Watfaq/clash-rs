use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, atomic::AtomicBool},
};

use rand::seq::IteratorRandom;
use watfaq_error::{Result, anyhow};
use watfaq_state::Context;
use watfaq_types::StackPrefer;

use crate::AbstractResolver;

pub struct SystemResolver {
    ipv6: AtomicBool,
}

/// SystemResolver is a resolver that uses libc getaddrinfo to resolve
/// hostnames.
impl SystemResolver {
    pub fn new(ipv6: bool) -> Result<Self> {
        Ok(Self {
            ipv6: AtomicBool::new(ipv6),
        })
    }
}

impl AbstractResolver for SystemResolver {
    async fn resolve(
        &self,
        host: &str,
        _: bool,
    ) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        let mut v4 = Vec::with_capacity(1);
        let mut v6 = Vec::with_capacity(1);
        let result = tokio::net::lookup_host(format!("{}:0", host)).await?;
        for ip in result {
            match ip {
                SocketAddr::V4(addr) => v4.push(*addr.ip()),
                SocketAddr::V6(addr) => v6.push(*addr.ip()),
            }
        }
        let v4 = v4.into_iter().choose(&mut rand::thread_rng());
        let v6 = v6.into_iter().choose(&mut rand::thread_rng());

        Ok((v4, v6))
    }

    async fn cached_for(&self, _: std::net::IpAddr) -> Option<String> {
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
