use crate::{
    dns::{
        ClashResolver, ThreadSafeDNSClient,
        dns_client::{DNSNetMode, DnsClient, Opts},
    },
    proxy::utils::{Interface, get_outbound_interface},
};
use std::sync::Arc;
use tracing::{debug, warn};

use super::config::NameServer;

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
                .unwrap_or_else(|| panic!("invalid address: {}", s.address));
            (host, port)
        };

        match DnsClient::new_client(Opts {
            r: resolver.as_ref().cloned(),
            host: host.to_string(),
            port: port
                .parse::<u16>()
                .unwrap_or_else(|_| panic!("no port for DNS server: {}", s.address)),
            net: s.net.to_owned(),
            iface: s
                .interface
                .as_ref()
                .and_then(|x| match x.as_str() {
                    "auto" => {
                        get_outbound_interface().map(|x| Interface::Name(x.name))
                    }
                    _ => Some(Interface::Name(x.to_owned())),
                })
                .inspect(|x| debug!("DNS client interface: {:?}", x)),
        })
        .await
        {
            Ok(c) => rv.push(c),
            Err(e) => warn!("initializing DNS client {} with error {}", &s, e),
        }
    }

    rv
}
