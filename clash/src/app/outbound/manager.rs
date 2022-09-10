use anyhow::Result;
use log::debug;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::proxy::reject;
use crate::{
    app::ThreadSafeDNSResolver,
    config::internal::proxy::{OutboundGroupProtocol, OutboundProxyProtocol},
    proxy::{direct, outbound::HandlerBuilder, socks, AnyOutboundHandler},
    Error,
};

pub struct OutboundManager {
    handlers: HashMap<String, AnyOutboundHandler>,
}

pub type ThreadSafeOutboundManager = Arc<RwLock<OutboundManager>>;

impl OutboundManager {
    pub fn new(
        outbounds: Vec<OutboundProxyProtocol>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        dns_client: ThreadSafeDNSResolver,
    ) -> Result<Self, Error> {
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
        _dns_client: ThreadSafeDNSResolver,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
    ) -> Result<(), Error> {
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

                OutboundProxyProtocol::Reject => {
                    handlers.insert(
                        "REJECT".to_string(),
                        HandlerBuilder::default()
                            .name("REJECT")
                            .stream_handler(Box::new(reject::StreamHandler))
                            .datagram_handler(Box::new(reject::DatagramHandler))
                            .build(),
                    );
                }

                OutboundProxyProtocol::Socks5(proto) => {
                    let stream = Box::new(socks::outbound::StreamHandler {
                        address: proto.server.clone(),
                        port: proto.port,
                    });
                    handlers.insert(
                        proto.name.clone(),
                        HandlerBuilder::default()
                            .name(proto.name.as_str())
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
                OutboundGroupProtocol::Relay(_proto) => todo!(),
                OutboundGroupProtocol::UrlTest(_proto) => todo!(),
                OutboundGroupProtocol::Fallback(_proto) => todo!(),
                OutboundGroupProtocol::LoadBalance(_proto) => todo!(),
                OutboundGroupProtocol::Select(_proto) => todo!(),
            }
        }
        Ok(())
    }
}
