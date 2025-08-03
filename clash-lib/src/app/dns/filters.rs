use std::{net, sync::Arc};

use crate::common::{mmdb::MmdbLookup, trie};

pub trait FallbackIPFilter: Sync + Send {
    fn apply(&self, ip: &net::IpAddr) -> bool;
}

pub struct GeoIPFilter(String, Option<MmdbLookup>);

impl GeoIPFilter {
    pub fn new(code: &str, mmdb: Option<MmdbLookup>) -> Self {
        Self(code.to_owned(), mmdb)
    }
}

impl FallbackIPFilter for GeoIPFilter {
    fn apply(&self, ip: &net::IpAddr) -> bool {
        !self.1.as_ref().is_some_and(|mmdb| {
            mmdb.lookup_country(*ip)
                .map(|x| x.country_code)
                .is_ok_and(|x| x == self.0)
        })
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

pub struct DomainFilter(trie::StringTrie<Option<String>>);

impl DomainFilter {
    pub fn new(domains: Vec<&str>) -> Self {
        let mut f = DomainFilter(trie::StringTrie::new());
        for d in domains {
            f.0.insert(d, Arc::new(None));
        }
        f
    }
}

impl FallbackDomainFilter for DomainFilter {
    fn apply(&self, domain: &str) -> bool {
        self.0.search(domain).is_some()
    }
}
