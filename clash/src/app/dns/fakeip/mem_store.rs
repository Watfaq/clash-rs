use std::{
    any::Any,
    net::{self, IpAddr},
};

use super::{FakeDns, Store};

pub struct InmemStore {
    itoh: lru_cache::LruCache<IpAddr, String>,
    htoi: lru_cache::LruCache<String, IpAddr>,
}

impl InmemStore {
    pub fn new(size: usize) -> Self {
        Self {
            itoh: lru_cache::LruCache::new(size),
            htoi: lru_cache::LruCache::new(size),
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

    fn copy_to(&self, store: &mut Box<dyn Store>) {
        if let Some(dst) = (store as &mut dyn Any).downcast_mut::<Self>() {
            dst.itoh = self.itoh.clone();
            dst.htoi = self.htoi.clone();
        }
    }
}
