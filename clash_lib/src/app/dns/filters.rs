use std::{net, sync::Arc};

use crate::common::{mmdb::Mmdb, trie};

pub trait FallbackIPFilter: Sync + Send {
    fn apply(&self, ip: &net::IpAddr) -> bool;
}

pub struct GeoIPFilter(String, Arc<Mmdb>);

impl GeoIPFilter {
    pub fn new(code: &str, mmdb: Arc<Mmdb>) -> Self {
        Self(code.to_owned(), mmdb)
    }
}

impl FallbackIPFilter for GeoIPFilter {
    fn apply(&self, ip: &net::IpAddr) -> bool {
        self.1
            .lookup_contry(*ip)
            .map(|x| x.country)
            .is_ok_and(|x| x.is_some_and(|x| x.iso_code == Some(self.0.as_str())))
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
