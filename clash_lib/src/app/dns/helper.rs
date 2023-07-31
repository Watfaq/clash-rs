use crate::dns::dns_client::{DNSNetMode, DnsClient, Opts};
use crate::dns::{ClashResolver, NameServer, ThreadSafeDNSClient};
use crate::proxy::utils::Interface;
use std::sync::Arc;
use tracing::{debug, error};

pub async fn make_clients(
    servers: Vec<NameServer>,
    resolver: Option<Arc<dyn ClashResolver>>,
) -> Vec<ThreadSafeDNSClient> {
    let mut rv = Vec::new();

    for s in servers {
        debug!("building nameserver: {:?}", s);

        let (host, port) = if s.net == DNSNetMode::DHCP {
            (s.address.as_str(), "0")
        } else {
            let port = s.address.split(":").last().unwrap();
            let host = s
                .address
                .strip_suffix(format!(":{}", port).as_str())
                .expect(format!("invalid address: {}", s.address).as_str());
            (host, port)
        };

        match DnsClient::new(Opts {
            r: resolver.as_ref().map(|x| x.clone()),
            host: host.to_string(),
            port: port
                .parse::<u16>()
                .expect(format!("no port for DNS server: {}", s.address).as_str()),
            net: s.net,
            iface: s.interface.map(|x| Interface::Name(x)),
        })
        .await
        {
            Ok(c) => rv.push(c),
            Err(e) => error!("initializing DNS client: {}", e),
        }
    }

    rv
}