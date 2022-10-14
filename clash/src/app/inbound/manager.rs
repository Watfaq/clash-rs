use crate::app::dispatcher::Dispatcher;
use crate::app::inbound::network_listener::{ListenerType, NetworkInboundListener};
use crate::app::nat_manager::NatManager;
use crate::config::internal::config::Inbound;
use crate::proxy::http;
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
        if let Some(http_port) = inbound.port {
            network_listeners.insert(
                "HTTP".to_string(),
                NetworkInboundListener {
                    name: "HTTP".to_string(),
                    bind_addr: inbound.bind_address,
                    port: http_port,
                    listener_type: ListenerType::HTTP,
                    dispatcher,
                    nat_manager,
                },
            );
        }

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
