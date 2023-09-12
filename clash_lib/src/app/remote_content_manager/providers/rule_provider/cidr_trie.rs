use std::net::{Ipv4Addr, Ipv6Addr};

use ip_network_table_deps_treebitmap::IpLookupTable;

pub struct CidrTrie {
    v4: IpLookupTable<Ipv4Addr, bool>,
    v6: IpLookupTable<Ipv6Addr, bool>,
}

impl CidrTrie {
    pub fn new() -> Self {
        Self {
            v4: IpLookupTable::new(),
            v6: IpLookupTable::new(),
        }
    }

    pub fn insert(&mut self, cidr: &str) -> bool {
        if let Ok(cidr) = cidr.parse::<ipnet::IpNet>() {
            match cidr {
                ipnet::IpNet::V4(v4) => {
                    self.v4.insert(v4.addr(), v4.prefix_len() as _, true);
                    true
                }
                ipnet::IpNet::V6(v6) => {
                    self.v6.insert(v6.addr(), v6.prefix_len() as _, true);
                    true
                }
            }
        } else {
            false
        }
    }
}
