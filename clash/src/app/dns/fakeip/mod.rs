use std::{net, sync::RwLock};

use crate::{
    app::dns::fakeip::{file_store::FileStore, mem_store::InmemStore},
    common::trie,
    Error,
};

use byteorder::{BigEndian, ByteOrder};

mod file_store;
mod mem_store;

pub struct Opts {
    pub ipnet: ipnet::IpNet,
    pub host: Option<trie::DomainTrie>,
    pub size: usize,
    pub persistence: bool,
}
pub struct FakeDns(RwLock<FakeDnsImpl>);

impl FakeDns {
    pub fn new(opt: Opts) -> Result<Self, Error> {
        let ip = match opt.ipnet.addr() {
            net::IpAddr::V4(ip) => ip,
            _ => unreachable!("fakeip range must be valid ipv4 subnet"),
        };
        let min = FakeDns::ip_to_uint(&ip) + 2;
        let prefix_len = opt.ipnet.prefix_len();
        let max_prefix_len = opt.ipnet.max_prefix_len();
        debug_assert_eq!(max_prefix_len, 32, "v4 subnet");
        let total = 1 << (max_prefix_len - prefix_len) - 2;

        let max = min + total - 1;

        let store: Box<dyn Store>;
        if opt.persistence {
            store = Box::new(InmemStore::new(opt.size));
        } else {
            store = Box::new(FileStore::new());
        }

        let inner = FakeDnsImpl {
            max,
            min,
            gateway: min - 1,
            offset: 0,
            host: opt.host,
            ipnet: opt.ipnet,
            store: store,
        };

        Ok(Self(RwLock::new(inner)))
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
    fn copy_to(&self, store: &mut Box<dyn Store>);
}

// Usage to FakeDnsImpl should be guarded by Mutex
struct FakeDnsImpl {
    max: u32,
    min: u32,
    gateway: u32,
    offset: u32,
    host: Option<trie::DomainTrie>,
    ipnet: ipnet::IpNet,
    store: Box<dyn Store>,
}

impl FakeDnsImpl {
    pub fn lookup(&mut self, host: &str) -> net::IpAddr {
        if let Some(ip) = self.store.get_by_host(host) {
            return ip;
        }

        let ip = self.get(host);
        self.store.pub_by_host(host, ip);
        return ip;
    }

    pub fn reverse_lookup(&mut self, ip: net::IpAddr) -> Option<String> {
        if !ip.is_ipv4() {
            None
        } else {
            self.store.get_by_ip(ip)
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
            self.store.exist(ip)
        }
    }

    pub fn gateway(&self) -> net::Ipv4Addr {
        net::Ipv4Addr::from(self.gateway)
    }

    pub fn ipnet(&self) -> ipnet::IpNet {
        self.ipnet
    }

    pub fn copy_from(&mut self, src: &FakeDnsImpl) {
        src.store.copy_to(&mut self.store)
    }

    fn get(&mut self, host: &str) -> net::IpAddr {
        let current = self.offset;

        loop {
            self.offset = (self.offset + 1) % (self.max - self.min);

            if self.offset == current {
                self.offset = (self.offset + 1) % (self.max - self.min);
                let ip = net::Ipv4Addr::from(self.min + self.offset - 1);
                self.store.del_by_ip(std::net::IpAddr::V4(ip));
                break;
            }

            let ip = net::Ipv4Addr::from(self.min + self.offset - 1);
            if !self.store.exist(std::net::IpAddr::V4(ip)) {
                break;
            }
        }

        let ip = net::Ipv4Addr::from(self.min + self.offset - 1);
        self.store.put_by_ip(std::net::IpAddr::V4(ip), host);
        std::net::IpAddr::V4(ip)
    }
}
