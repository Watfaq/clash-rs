use crate::{
    app::net::DEFAULT_OUTBOUND_INTERFACE,
    config::proxy::PROXY_DIRECT,
    dns::{
        ClashResolver, EdnsClientSubnet, ThreadSafeDNSClient,
        dns_client::{DNSNetMode, DnsClient, Opts},
    },
    proxy,
};
use hickory_proto::rr::rdata::opt::EdnsCode;
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, warn};

use super::config::NameServer;
use crate::print_and_exit;

pub async fn make_clients(
    servers: Vec<NameServer>,
    resolver: Option<Arc<dyn ClashResolver>>,
    outbounds: HashMap<String, Arc<dyn crate::proxy::OutboundHandler>>,
    edns_client_subnet: Option<EdnsClientSubnet>,
    fw_mark: Option<u32>,
) -> Vec<ThreadSafeDNSClient> {
    let mut rv = Vec::new();

    for s in servers {
        debug!("building nameserver: {}", s);

        let proxy = outbounds
            .get(&s.proxy.clone().unwrap_or(PROXY_DIRECT.to_string()))
            .cloned()
            .unwrap_or(Arc::new(proxy::direct::Handler::new(PROXY_DIRECT)));

        let (host, port) = if s.net == DNSNetMode::Dhcp {
            (s.address.as_str(), "0")
        } else {
            let port = s.address.split(':').next_back().unwrap();
            let host = s
                .address
                .strip_suffix(format!(":{port}").as_str())
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
            proxy,
            ecs: edns_client_subnet.clone(),
            fw_mark,
        })
        .await
        {
            Ok(c) => rv.push(c),
            Err(e) => warn!("initializing DNS client {} with error {}", &s, e),
        }
    }

    rv
}

pub fn build_dns_response_message(
    req: &hickory_proto::op::Message,
    recursive_available: bool,
    authoritative: bool,
) -> hickory_proto::op::Message {
    let mut res = hickory_proto::op::Message::new();

    res.set_id(req.id());
    res.set_op_code(req.op_code());
    res.set_message_type(hickory_proto::op::MessageType::Response);
    res.add_queries(req.queries().iter().cloned());
    res.set_recursion_available(recursive_available);
    res.set_authoritative(authoritative);
    res.set_recursion_desired(req.recursion_desired());
    res.set_checking_disabled(req.checking_disabled());
    if let Some(edns) = req.extensions().clone() {
        res.set_edns(edns);
    }

    if let Some(edns) = res.extensions_mut() {
        // Remove only padding options, keep everything else
        edns.options_mut().remove(EdnsCode::Padding);
    }

    res
}
