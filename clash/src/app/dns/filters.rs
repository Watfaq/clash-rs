use std::{net, sync::Arc};

use crate::common::trie;

pub trait FallbackIPFilter: Sync + Send {
    fn apply(&self, ip: &net::IpAddr) -> bool;
}

pub struct GeoIPFilter(String);

impl GeoIPFilter {
    pub fn new(code: &str) -> Self {
        Self(code.to_owned())
    }
}

impl FallbackIPFilter for GeoIPFilter {
    fn apply(&self, _ip: &net::IpAddr) -> bool {
        todo!("mmdb not implemented yet")
    }
}

pub struct IPNetFilter(ipnet::IpNet);

impl IPNetFilter {
    pub fn new(ipnet: ipnet::IpNet) -> Self {
        Self(ipnet)
    }
}

impl FallbackIPFilter for IPNetFilter {
    fn apply(&self, ip: &net::IpAddr) -> bool {
        self.0.contains(ip)
    }
}

pub trait FallbackDomainFilter: Sync + Send {
    fn apply(&self, domain: &str) -> bool;
}

pub struct DomainFilter(trie::DomainTrie);

impl DomainFilter {
    pub fn new(domains: Vec<&str>) -> Self {
        let mut f = DomainFilter(trie::DomainTrie::new());
        for d in domains {
            f.0.insert(d, Arc::new(""));
        }
        f
    }
}

impl FallbackDomainFilter for DomainFilter {
    fn apply(&self, domain: &str) -> bool {
        self.0.search(domain).is_some()
    }
}
