use crate::app::dispatcher::Dispatcher;
use crate::app::inbound::network_listener::NetworkInboundListener;
use crate::app::nat_manager::NatManager;
use crate::config::internal::config::Inbound;
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
        todo!()
    }

    pub fn get_runners(&self) -> Result<Vec<Runner>, Error> {
        let mut runners = Vec::new();
        for r in self.network_listeners.values() {
            runners.append(&mut r.listen()?);
        }
        Ok(runners)
    }
}
