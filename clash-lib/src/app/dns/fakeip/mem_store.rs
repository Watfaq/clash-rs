use std::net::IpAddr;

use async_trait::async_trait;

use super::Store;

pub struct InMemStore {
    itoh: lru_time_cache::LruCache<IpAddr, String>,
    htoi: lru_time_cache::LruCache<String, IpAddr>,
}

impl InMemStore {
    pub fn new(size: usize) -> Self {
        Self {
            itoh: lru_time_cache::LruCache::with_capacity(size),
            htoi: lru_time_cache::LruCache::with_capacity(size),
        }
    }
}

#[async_trait]
impl Store for InMemStore {
    async fn get_by_host(&mut self, host: &str) -> Option<std::net::IpAddr> {
        self.htoi.get_mut(host).map(|ip| {
            self.itoh.get_mut(ip);
            *ip
        })
    }

    async fn pub_by_host(&mut self, host: &str, ip: std::net::IpAddr) {
        self.htoi.insert(host.into(), ip);
    }

    async fn get_by_ip(&mut self, ip: std::net::IpAddr) -> Option<String> {
        self.itoh.get_mut(&ip).map(|h| {
            self.htoi.get_mut(h);
            h.to_string()
        })
    }

    async fn put_by_ip(&mut self, ip: std::net::IpAddr, host: &str) {
        self.itoh.insert(ip, host.into());
    }

    async fn del_by_ip(&mut self, ip: std::net::IpAddr) {
        if let Some(host) = self.itoh.remove(&ip) {
            self.htoi.remove(&host);
        }
    }

    async fn exist(&mut self, ip: std::net::IpAddr) -> bool {
        self.itoh.contains_key(&ip)
    }

    async fn copy_to(&self, #[allow(unused)] store: &mut Box<dyn Store>) {
        // TODO: copy
        // NOTE: use file based persistence store
    }
}
