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
        let ip = self.htoi.get_mut(host)?;
        let ip_copy = *ip;
        // Cross-check: if itoh doesn't map this IP back to the same host,
        // the entry is stale (e.g. htoi survived but itoh was evicted and
        // the IP was reassigned).  Treat as a miss and clean up.
        if self.itoh.get(&ip_copy).map(|h| h.as_str()) != Some(host) {
            self.htoi.remove(host);
            return None;
        }
        // Touch itoh LRU to keep access ordering in sync.
        self.itoh.get_mut(&ip_copy);
        Some(ip_copy)
    }

    async fn pub_by_host(&mut self, host: &str, ip: std::net::IpAddr) {
        // Maintain bidirectional invariant: remove stale mappings that
        // referenced the old host or IP before inserting the new pair.
        if let Some(old_host) = self.itoh.remove(&ip) {
            if old_host != host {
                self.htoi.remove(&old_host);
            }
        }
        if let Some(old_ip) = self.htoi.remove(host) {
            if old_ip != ip {
                self.itoh.remove(&old_ip);
            }
        }
        self.itoh.insert(ip, host.into());
        self.htoi.insert(host.into(), ip);
    }

    async fn get_by_ip(&mut self, ip: std::net::IpAddr) -> Option<String> {
        let host = self.itoh.get_mut(&ip)?;
        let host_copy = host.clone();
        // Cross-check: if htoi doesn't map this host back to the same IP,
        // the entry is stale.
        if self.htoi.get(&host_copy).map(|x| *x) != Some(ip) {
            self.itoh.remove(&ip);
            return None;
        }
        // Touch htoi LRU to keep access ordering in sync.
        self.htoi.get_mut(&host_copy);
        Some(host_copy)
    }

    async fn put_by_ip(&mut self, ip: std::net::IpAddr, host: &str) {
        // Maintain bidirectional invariant: remove stale mappings that
        // referenced the old host or IP before inserting the new pair.
        if let Some(old_host) = self.itoh.remove(&ip) {
            if old_host != host {
                self.htoi.remove(&old_host);
            }
        }
        if let Some(old_ip) = self.htoi.remove(host) {
            if old_ip != ip {
                self.itoh.remove(&old_ip);
            }
        }
        self.itoh.insert(ip, host.into());
        self.htoi.insert(host.into(), ip);
    }

    async fn del_by_ip(&mut self, ip: std::net::IpAddr) {
        if let Some(host) = self.itoh.remove(&ip) {
            self.htoi.remove(&host);
        }
    }

    async fn exist(&mut self, ip: std::net::IpAddr) -> bool {
        // An IP exists only if both forward and reverse mappings agree.
        match self.itoh.get(&ip) {
            Some(host) => self.htoi.get(host).map(|x| *x) == Some(ip),
            None => false,
        }
    }

    async fn copy_to(&self, #[allow(unused)] store: &mut Box<dyn Store>) {
        // TODO: copy
        // NOTE: use file based persistence store
    }
}
