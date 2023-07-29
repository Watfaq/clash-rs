use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use crate::config::internal::proxy::{PROXY_DIRECT, PROXY_REJECT};
use crate::proxy::{reject, shadowsocks, CommonOption};
use crate::{
    app::ThreadSafeDNSResolver,
    config::internal::proxy::{OutboundGroupProtocol, OutboundProxyProtocol},
    proxy::{direct, AnyOutboundHandler},
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
                    handlers.insert(PROXY_DIRECT.to_string(), direct::Handler::new());
                }

                OutboundProxyProtocol::Reject => {
                    handlers.insert(PROXY_REJECT.to_string(), reject::Handler::new());
                }

                OutboundProxyProtocol::Ss(s) => {
                    handlers.insert(s.name.clone(), s.try_into()?);
                }

                p => {
                    debug!("proto {} not supported yet", p);
                }
            }
        }

        for outbound_group in outbound_groups.iter() {
            match outbound_group {
                OutboundGroupProtocol::Relay(_proto) => {}
                OutboundGroupProtocol::UrlTest(_proto) => todo!(),
                OutboundGroupProtocol::Fallback(_proto) => todo!(),
                OutboundGroupProtocol::LoadBalance(_proto) => todo!(),
                OutboundGroupProtocol::Select(_proto) => todo!(),
            }
        }
        Ok(())
    }
}
