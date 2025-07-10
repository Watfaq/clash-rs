use crate::{
    app::net::DEFAULT_OUTBOUND_INTERFACE,
    dns::{
        ClashResolver, ThreadSafeDNSClient,
        dns_client::{DNSNetMode, DnsClient, Opts},
    },
};
use std::sync::Arc;
use tracing::{debug, warn};

use super::config::NameServer;
use crate::print_and_exit;

pub async fn make_clients(
    servers: Vec<NameServer>,
    resolver: Option<Arc<dyn ClashResolver>>,
) -> Vec<ThreadSafeDNSClient> {
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
                .unwrap_or_else(|| {
                    print_and_exit!("invalid address: {}", s.address);
                });
            (host, port)
        };

        match DnsClient::new_client(Opts {
            r: resolver.as_ref().cloned(),
            host: host.to_string(),
            port: port.parse::<u16>().unwrap_or_else(|_| {
                print_and_exit!("invalid port: {}", port);
            }),
            net: s.net.to_owned(),
            iface: s
                .interface
                .as_ref()
                .or(DEFAULT_OUTBOUND_INTERFACE.read().await.as_ref())
                .inspect(|x| debug!("DNS client interface: {:?}", x))
                .cloned(),
        })
        .await
        {
            Ok(c) => rv.push(c),
            Err(e) => warn!("initializing DNS client {} with error {}", &s, e),
        }
    }

    rv
}
