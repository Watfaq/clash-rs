use std::{cell::RefCell, net};

use crate::{
    app::dns::fakeip::{mem_store::InmemStore},
    common::trie,
    Error,
};

use byteorder::{BigEndian, ByteOrder};
use tokio::sync::RwLock;

mod file_store;
mod mem_store;

pub struct Opts {
    pub ipnet: ipnet::IpNet,
    pub host: Option<trie::DomainTrie>,
    pub size: usize,
    pub persistence: bool,
    pub db_path: Option<String>,
}
pub struct FakeDns(RwLock<FakeDnsImpl>);

impl FakeDns {
    pub fn new(opt: Opts) -> Result<Self, Error> {
        let ip = match opt.ipnet.network() {
            net::IpAddr::V4(ip) => ip,
            _ => unreachable!("fakeip range must be valid ipv4 subnet"),
        };
        let min = FakeDns::ip_to_uint(&ip) + 2;
        let prefix_len = opt.ipnet.prefix_len();
        let max_prefix_len = opt.ipnet.max_prefix_len();
        debug_assert_eq!(max_prefix_len, 32, "v4 subnet");
        let total = (1 << (max_prefix_len - prefix_len)) - 2;

        let max = min + total - 1;

        let store: RefCell<Box<dyn Store>>;
        if !opt.persistence {
            store = RefCell::new(Box::new(InmemStore::new(opt.size)));
        } else {
            return Err(Error::InvalidConfig(anyhow!(
                "do not support fakeip range persistent(yet)"
            )));
        }

        let inner = FakeDnsImpl {
            max,
            min,
            gateway: min - 1,
            offset: 0,
            host: opt.host,
            ipnet: opt.ipnet,
            store,
        };

        Ok(Self(RwLock::new(inner)))
    }

    pub async fn lookup(&self, host: &str) -> net::IpAddr {
        self.0.write().await.lookup(host)
    }

    pub async fn reverse_lookup(&mut self, ip: net::IpAddr) -> Option<String> {
        self.0.write().await.reverse_lookup(ip)
    }

    pub async fn should_skip(&self, domain: &str) -> bool {
        self.0.read().await.should_skip(domain)
    }

    pub async fn exist(&mut self, ip: net::IpAddr) -> bool {
        self.0.write().await.exist(ip)
    }

    pub async fn gateway(&self) -> net::Ipv4Addr {
        self.0.read().await.gateway()
    }

    pub async fn ipnet(&self) -> ipnet::IpNet {
        self.0.read().await.ipnet()
    }

    pub async fn copy_from(&mut self, src: &FakeDns) {
        self.0
            .write()
            .await
            .copy_from(&src.0.write().await.get_mut())
    }

    fn ip_to_uint(ip: &net::Ipv4Addr) -> u32 {
        BigEndian::read_u32(&ip.octets())
    }
}

trait Store {
    fn get_by_host(&mut self, host: &str) -> Option<net::IpAddr>;
    fn pub_by_host(&mut self, host: &str, ip: net::IpAddr);
    fn get_by_ip(&mut self, ip: net::IpAddr) -> Option<String>;
    fn put_by_ip(&mut self, ip: net::IpAddr, host: &str);
    fn del_by_ip(&mut self, ip: net::IpAddr);
    fn exist(&mut self, ip: net::IpAddr) -> bool;
    fn copy_to(&self, store: &mut RefCell<Box<dyn Store>>);
}

// Usage to FakeDnsImpl should be guarded by Mutex
struct FakeDnsImpl {
    max: u32,
    min: u32,
    gateway: u32,
    offset: u32,
    host: Option<trie::DomainTrie>,
    ipnet: ipnet::IpNet,
    store: RefCell<Box<dyn Store>>,
}

impl FakeDnsImpl {
    pub fn lookup(&mut self, host: &str) -> net::IpAddr {
        if let Some(ip) = self.store.borrow_mut().get_by_host(host) {
            return ip;
        }

        let ip = self.get(host);
        self.store.borrow_mut().pub_by_host(host, ip);
        return ip;
    }

    pub fn reverse_lookup(&mut self, ip: net::IpAddr) -> Option<String> {
        if !ip.is_ipv4() {
            None
        } else {
            self.store.borrow_mut().get_by_ip(ip)
        }
    }

    pub fn should_skip(&self, domain: &str) -> bool {
        match &self.host {
            None => false,
            Some(host) => host.search(domain).is_some(),
        }
    }

    pub fn exist(&mut self, ip: net::IpAddr) -> bool {
        if !ip.is_ipv4() {
            false
        } else {
            self.store.borrow_mut().exist(ip)
        }
    }

    pub fn gateway(&self) -> net::Ipv4Addr {
        net::Ipv4Addr::from(self.gateway)
    }

    pub fn ipnet(&self) -> ipnet::IpNet {
        self.ipnet
    }

    pub fn copy_from(&mut self, src: &FakeDnsImpl) {
        src.store.borrow().copy_to(&mut self.store)
    }

    fn get(&mut self, host: &str) -> net::IpAddr {
        let current = self.offset;

        loop {
            self.offset = (self.offset + 1) % (self.max - self.min);

            if self.offset == current {
                self.offset = (self.offset + 1) % (self.max - self.min);
                let ip = net::Ipv4Addr::from(self.min + self.offset - 1);
                self.store.borrow_mut().del_by_ip(std::net::IpAddr::V4(ip));
                break;
            }

            let ip = net::Ipv4Addr::from(self.min + self.offset - 1);
            if !self.store.borrow_mut().exist(std::net::IpAddr::V4(ip)) {
                break;
            }
        }

        let ip = net::Ipv4Addr::from(self.min + self.offset - 1);
        self.store
            .borrow_mut()
            .put_by_ip(std::net::IpAddr::V4(ip), host);
        std::net::IpAddr::V4(ip)
    }

    fn get_mut(&mut self) -> &mut Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{net, rc::Rc};

    use crate::{common::trie};

    use super::{FakeDns, Opts};

    #[tokio::test]
    async fn test_inmem_basic() {
        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            host: None,
            size: 10,
            persistence: false,
            db_path: None,
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
        assert_eq!(pool.gateway().await, net::IpAddr::from([192, 168, 0, 1]));
        assert_eq!(pool.ipnet().await.to_string(), ipnet.to_string());
        assert!(pool.exist(net::IpAddr::from([192, 168, 0, 3])).await);
        assert!(!pool.exist(net::IpAddr::from([192, 168, 0, 4])).await);
        assert!(!pool.exist("::1".parse().unwrap()).await);
    }

    #[tokio::test]
    async fn test_inmem_cycle_used() {
        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let pool = FakeDns::new(Opts {
            ipnet,
            host: None,
            size: 10,
            persistence: false,
            db_path: None,
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
        let ipnet = "192.168.0.0/30".parse::<ipnet::IpNet>().unwrap();
        let mut tree = trie::DomainTrie::new();
        tree.insert("example.com", Rc::new(0));

        let pool = FakeDns::new(Opts {
            ipnet,
            host: Some(tree),
            size: 10,
            persistence: false,
            db_path: None,
        })
        .unwrap();

        assert!(pool.should_skip("example.com").await);
        assert!(!pool.should_skip("foo.com").await);
    }

    #[tokio::test]
    async fn test_pool_max_cache_size() {
        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let pool = FakeDns::new(Opts {
            ipnet,
            host: None,
            size: 2,
            persistence: false,
            db_path: None,
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
        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let pool = FakeDns::new(Opts {
            ipnet,
            host: None,
            size: 2,
            persistence: false,
            db_path: None,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;
        let last = pool.lookup("bar.com").await;
        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));

        let mut new_pool = FakeDns::new(Opts {
            ipnet,
            host: None,
            size: 2,
            persistence: false,
            db_path: None,
        })
        .unwrap();

        new_pool.copy_from(&pool).await;

        assert!(new_pool.reverse_lookup(first).await.is_some());
        assert!(new_pool.reverse_lookup(last).await.is_some());
    }
}
