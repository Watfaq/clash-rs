use std::{cell::RefCell, net::IpAddr};

use super::Store;

pub struct InmemStore {
    itoh: lru_time_cache::LruCache<IpAddr, String>,
    htoi: lru_time_cache::LruCache<String, IpAddr>,
}

impl InmemStore {
    pub fn new(size: usize) -> Self {
        Self {
            itoh: lru_time_cache::LruCache::with_capacity(size),
            htoi: lru_time_cache::LruCache::with_capacity(size),
        }
    }
}

impl Store for InmemStore {
    fn get_by_host(&mut self, host: &str) -> Option<std::net::IpAddr> {
        self.htoi.get_mut(host).map(|ip| {
            self.itoh.get_mut(ip);
            *ip
        })
    }

    fn pub_by_host(&mut self, host: &str, ip: std::net::IpAddr) {
        self.htoi.insert(host.into(), ip);
    }

    fn get_by_ip(&mut self, ip: std::net::IpAddr) -> Option<String> {
        self.itoh.get_mut(&ip).map(|h| {
            self.htoi.get_mut(h);
            h.to_string()
        })
    }

    fn put_by_ip(&mut self, ip: std::net::IpAddr, host: &str) {
        self.itoh.insert(ip, host.into());
    }

    fn del_by_ip(&mut self, ip: std::net::IpAddr) {
        if let Some(host) = self.itoh.remove(&ip) {
            self.htoi.remove(&host);
        }
    }

    fn exist(&mut self, ip: std::net::IpAddr) -> bool {
        self.itoh.contains_key(&ip)
    }

    fn copy_to(&self, _store: &mut RefCell<Box<dyn Store>>) {
        todo!("not implemented yet")
    }
}
