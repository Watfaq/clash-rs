use crate::app::dispatcher::Dispatcher;
use crate::app::inbound::network_listener::NetworkInboundListener;
use crate::app::nat_manager::NatManager;
use crate::config::internal::config::Inbound;
use crate::proxy::socks;
use crate::{proxy, Error, Runner};
use std::collections::HashMap;
use std::sync::Arc;

pub struct InboundManager {
    network_listeners: HashMap<String, NetworkInboundListener>,
}

impl InboundManager {
    pub fn new(
        inbound: Inbound,
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
    ) -> Result<Self, Error> {
        let mut network_listeners = HashMap::new();

        if let Some(socks_port) = inbound.socks_port {
            let stream = Arc::new(socks::inbound::StreamHandler);
            let datagram = Arc::new(socks::inbound::DatagramHandler);
            let handler = Arc::new(proxy::inbound::Handler::new(
                "socks",
                Some(stream),
                Some(datagram),
            ));
            network_listeners.insert(
                "socks".to_string(),
                NetworkInboundListener {
                    name: "SOCKS5".to_string(),
                    bind_addr: inbound.bind_address,
                    port: socks_port,
                    handler,
                    dispatcher,
                    nat_manager,
                },
            );
        };

        Ok(Self { network_listeners })
    }

    pub fn get_runners(&self) -> Result<Vec<Runner>, Error> {
        let mut runners = Vec::new();
        for r in self.network_listeners.values() {
            runners.append(&mut r.listen()?);
        }
        Ok(runners)
    }
}
