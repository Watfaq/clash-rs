use anyhow::Result;
use log::debug;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    app::ThreadSafeAsyncDnsClient,
    config::internal::proxy::{OutboundGroupProtocol, OutboundProxyProtocol},
    proxy::{direct, outbound::HandlerBuilder, socks, AnyOutboundHandler},
};

pub struct OutboundManager {
    handlers: HashMap<String, AnyOutboundHandler>,
}

pub type ThreadSafeOutboundManager = Arc<RwLock<OutboundManager>>;

impl OutboundManager {
    pub fn new(
        outbounds: Vec<OutboundProxyProtocol>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        dns_client: ThreadSafeAsyncDnsClient,
    ) -> Result<Self> {
        let mut handlers = HashMap::new();

        OutboundManager::load_handlers(outbounds, outbound_groups, dns_client, &mut handlers)?;

        Ok(Self { handlers })
    }

    pub fn get(&self, name: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(name).map(Clone::clone)
    }

    fn load_handlers(
        outbounds: Vec<OutboundProxyProtocol>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        dns_client: ThreadSafeAsyncDnsClient,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
    ) -> Result<()> {
        for outbound in outbounds.iter() {
            match outbound {
                OutboundProxyProtocol::Direct => {
                    handlers.insert(
                        "DIRECT".to_string(),
                        HandlerBuilder::default()
                            .name("DIRECT")
                            .stream_handler(Box::new(direct::StreamHandler))
                            .datagram_handler(Box::new(direct::DatagramHandler))
                            .build(),
                    );
                }

                OutboundProxyProtocol::Socks5(name, proto) => {
                    let stream = Box::new(socks::outbound::StreamHandler {
                        address: proto.server,
                        port: proto.port,
                    });
                    handlers.insert(
                        name.to_string(),
                        HandlerBuilder::default()
                            .name(name.as_str())
                            .stream_handler(stream)
                            .build(),
                    );
                }
                p => {
                    debug!("proto {} not supported yet", p);
                }
            }
        }

        for outbound_group in outbound_groups.iter() {
            match outbound_group {
                OutboundGroupProtocol::Relay(name, _) => todo!(),
                OutboundGroupProtocol::UrlTest(name, _) => todo!(),
                OutboundGroupProtocol::Fallback(name, _) => todo!(),
                OutboundGroupProtocol::LoadBalance(name, _) => todo!(),
                OutboundGroupProtocol::Select(name, _) => todo!(),
            }
        }
        Ok(())
    }
}
