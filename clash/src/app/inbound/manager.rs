use crate::app::dispatcher::Dispatcher;
use crate::app::inbound::network_listener::NetworkInboundListener;
use crate::app::nat_manager::NatManager;
use crate::config::internal::config::Inbound;
use crate::proxy;
use crate::proxy::socks;
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
    ) -> anyhow::Result<Self> {
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
                "socks",
                NetworkInboundListener {
                    bind_addr: inbound.bind_address,
                    handler,
                    dispatcher,
                    nat_manager,
                },
            );
        };

        Ok(Self {
            network_listeners: Default::default(),
        })
    }
}
