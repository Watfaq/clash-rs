use crate::{
    DnsClient, Resolver,
    dns::dns_client::{DNSNetMode, EnhancedDnsClient, Opts},
};
use std::sync::Arc;
use tracing::{debug, warn};

use super::config::NameServer;

pub async fn build_dns_clients(
    servers: Vec<NameServer>,
    resolver: &Resolver,
) -> Vec<DnsClient> {
    let mut rv = Vec::new();
    for s in servers {
        debug!("building nameserver: {}", s);

        let (host, port) = if s.net == DNSNetMode::Dhcp {
            (s.address.as_str(), "0")
        } else {
            let port = s.address.split(':').next_back().unwrap();
            let host = s
                .address
                .strip_suffix(format!(":{}", port).as_str())
                .unwrap_or_else(|| panic!("invalid address: {}", s.address));
            (host, port)
        };
        match EnhancedDnsClient::new(
            resolver,
            Opts {
                host: host.to_string(),
                port: port.parse::<u16>().unwrap_or_else(|_| {
                    panic!("no port for DNS server: {}", s.address)
                }),
                net: s.net.to_owned(),
            },
        )
        .await
        {
            Ok(c) => rv.push(c),
            Err(e) => warn!("initializing DNS client {} with error {}", &s, e),
        }
    }

    rv
}
