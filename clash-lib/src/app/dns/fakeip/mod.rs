use std::{net, sync::Arc};

use crate::{Error, common::trie};

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use tokio::sync::RwLock;

mod file_store;
mod mem_store;

pub use file_store::FileStore;
pub use mem_store::InMemStore;

pub struct Opts {
    pub ipnet: ipnet::IpNet,
    pub skipped_hostnames: Option<trie::StringTrie<bool>>,
    pub store: Box<dyn Store>,
}

#[async_trait]
pub trait Store: Sync + Send {
    async fn get_by_host(&mut self, host: &str) -> Option<net::IpAddr>;
    async fn pub_by_host(&mut self, host: &str, ip: net::IpAddr);
    async fn get_by_ip(&mut self, ip: net::IpAddr) -> Option<String>;
    async fn put_by_ip(&mut self, ip: net::IpAddr, host: &str);
    async fn del_by_ip(&mut self, ip: net::IpAddr);
    async fn exist(&mut self, ip: net::IpAddr) -> bool;
    async fn copy_to(&self, store: &mut Box<dyn Store>);
}

pub type ThreadSafeFakeDns = Arc<RwLock<FakeDns>>;

pub struct FakeDns {
    max: u32,
    min: u32,
    #[allow(dead_code)]
    gateway: u32,
    offset: u32,
    skipped_hostnames: Option<trie::StringTrie<bool>>,
    ipnet: ipnet::IpNet,
    store: Box<dyn Store>,
}

impl FakeDns {
    pub fn new(opt: Opts) -> Result<Self, Error> {
        let ip = match opt.ipnet.network() {
            net::IpAddr::V4(ip) => ip,
            _ => unreachable!("fakeip range must be valid ipv4 subnet"),
        };
        let min = Self::ip_to_uint(&ip) + 2;
        let prefix_len = opt.ipnet.prefix_len();
        let max_prefix_len = opt.ipnet.max_prefix_len();
        debug_assert_eq!(max_prefix_len, 32, "v4 subnet");
        let total = (1 << (max_prefix_len - prefix_len)) - 2;

        let max = min + total - 1;

        Ok(Self {
            max,
            min,
            gateway: min - 1,
            offset: 0,
            skipped_hostnames: opt.skipped_hostnames,
            ipnet: opt.ipnet,
            store: opt.store,
        })
    }

    pub async fn lookup(&mut self, host: &str) -> net::IpAddr {
        if let Some(ip) = self.store.get_by_host(host).await {
            return ip;
        }

        let ip = self.get(host).await;
        self.store.pub_by_host(host, ip).await;
        ip
    }

    pub async fn reverse_lookup(&mut self, ip: net::IpAddr) -> Option<String> {
        if !ip.is_ipv4() {
            None
        } else {
            self.store.get_by_ip(ip).await
        }
    }

    pub fn should_skip(&self, domain: &str) -> bool {
        match &self.skipped_hostnames {
            None => false,
            Some(host) => host.search(domain).is_some(),
        }
    }

    #[allow(dead_code)]
    pub async fn exist(&mut self, ip: net::IpAddr) -> bool {
        if !ip.is_ipv4() {
            false
        } else {
            self.store.exist(ip).await
        }
    }

    pub async fn is_fake_ip(&mut self, ip: net::IpAddr) -> bool {
        if !ip.is_ipv4() {
            false
        } else {
            self.ipnet.contains(&ip)
        }
    }

    #[allow(dead_code)]
    pub fn gateway(&self) -> net::Ipv4Addr {
        net::Ipv4Addr::from(self.gateway)
    }

    #[allow(dead_code)]
    pub fn ipnet(&self) -> ipnet::IpNet {
        self.ipnet
    }

    #[allow(dead_code)]
    pub async fn copy_from(&mut self, src: &Self) {
        src.store.copy_to(&mut self.store).await;
    }

    async fn get(&mut self, host: &str) -> net::IpAddr {
        let current = self.offset;

        loop {
            self.offset = (self.offset + 1) % (self.max - self.min);

            if self.offset == current {
                self.offset = (self.offset + 1) % (self.max - self.min);
                let ip = net::Ipv4Addr::from(self.min + self.offset - 1);
                self.store.del_by_ip(std::net::IpAddr::V4(ip)).await;
                break;
            }

            let ip = net::Ipv4Addr::from(self.min + self.offset - 1);
            if !self.store.exist(std::net::IpAddr::V4(ip)).await {
                break;
            }
        }

        let ip = net::Ipv4Addr::from(self.min + self.offset - 1);
        self.store.put_by_ip(std::net::IpAddr::V4(ip), host).await;
        std::net::IpAddr::V4(ip)
    }

    fn ip_to_uint(ip: &net::Ipv4Addr) -> u32 {
        BigEndian::read_u32(&ip.octets())
    }
}

#[cfg(test)]
mod tests {
    use std::{net, sync::Arc};

    use crate::{app::dns::fakeip::mem_store::InMemStore, common::trie};

    use super::{FakeDns, Opts};

    #[tokio::test]
    async fn test_inmem_basic() {
        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let store = Box::new(InMemStore::new(10));
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;
        let last = pool.lookup("bar.com").await;

        let bar = pool.reverse_lookup(last).await;

        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(
            pool.lookup("foo.com").await,
            net::IpAddr::from([192, 168, 0, 2])
        );
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));
        assert!(bar.is_some());
        assert_eq!(bar, Some("bar.com".into()));
        assert_eq!(pool.gateway(), net::IpAddr::from([192, 168, 0, 1]));
        assert_eq!(pool.ipnet().to_string(), ipnet.to_string());
        assert!(pool.exist(net::IpAddr::from([192, 168, 0, 3])).await);
        assert!(!pool.exist(net::IpAddr::from([192, 168, 0, 4])).await);
        assert!(!pool.exist("::1".parse().unwrap()).await);
    }

    #[tokio::test]
    async fn test_inmem_cycle_used() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let foo = pool.lookup("foo.com").await;
        let bar = pool.lookup("bar.com").await;

        for i in 0..3 {
            pool.lookup(&format!("{}.com", i)).await;
        }

        let baz = pool.lookup("baz.com").await;
        let next = pool.lookup("foo.com").await;
        assert_eq!(foo, baz);
        assert_eq!(next, bar);
    }

    #[tokio::test]
    async fn test_pool_skip() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "192.168.0.0/30".parse::<ipnet::IpNet>().unwrap();
        let mut tree = trie::StringTrie::new();
        tree.insert("example.com", Arc::new(false));

        let pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: Some(tree),
            store,
        })
        .unwrap();

        assert!(pool.should_skip("example.com"));
        assert!(!pool.should_skip("foo.com"));
    }

    #[tokio::test]
    async fn test_pool_max_cache_size() {
        let store = Box::new(InMemStore::new(2));

        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;

        pool.lookup("bar.com").await;
        pool.lookup("baz.com").await;
        let next = pool.lookup("foo.com").await;

        assert_ne!(first, next);
    }

    #[tokio::test]
    #[ignore = "copy not implemented"]
    async fn test_pool_clone() {
        let store = Box::new(InMemStore::new(2));

        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;
        let last = pool.lookup("bar.com").await;
        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));

        let store = Box::new(InMemStore::new(2));

        let mut new_pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        new_pool.copy_from(&pool).await;

        assert!(new_pool.reverse_lookup(first).await.is_some());
        assert!(new_pool.reverse_lookup(last).await.is_some());
    }
}
