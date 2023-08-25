use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::app::dispatcher::Dispatcher;
use crate::app::inbound::network_listener::{ListenerType, NetworkInboundListener};
use crate::config::internal::config::Inbound;
use crate::{Error, Runner};
use std::collections::HashMap;
use std::sync::Arc;

pub struct InboundManager {
    network_listeners: HashMap<String, NetworkInboundListener>,
}

pub type ThreadSafeInboundManager = Arc<Mutex<InboundManager>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ports {
    port: Option<u16>,
    #[serde(rename = "socks-port")]
    socks_port: Option<u16>,
    #[serde(rename = "redir-port")]
    redir_port: Option<u16>,
    #[serde(rename = "tproxy-port")]
    tproxy_port: Option<u16>,
    #[serde(rename = "mixed-port")]
    mixed_port: Option<u16>,
}

impl InboundManager {
    pub fn new(inbound: Inbound, dispatcher: Arc<Dispatcher>) -> Result<Self, Error> {
        let mut network_listeners = HashMap::new();
        if let Some(http_port) = inbound.port {
            network_listeners.insert(
                "HTTP".to_string(),
                NetworkInboundListener {
                    name: "HTTP".to_string(),
                    bind_addr: inbound.bind_address.clone(),
                    port: http_port,
                    listener_type: ListenerType::HTTP,
                    dispatcher: dispatcher.clone(),
                },
            );
        }

        if let Some(socks_port) = inbound.socks_port {
            network_listeners.insert(
                "SOCKS5".to_string(),
                NetworkInboundListener {
                    name: "SOCKS5".to_string(),
                    bind_addr: inbound.bind_address,
                    port: socks_port,
                    listener_type: ListenerType::SOCKS5,
                    dispatcher: dispatcher.clone(),
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

    pub fn get_ports(&self) -> Ports {
        let mut ports = Ports {
            port: None,
            socks_port: None,
            redir_port: None,
            tproxy_port: None,
            mixed_port: None,
        };
        self.network_listeners
            .values()
            .for_each(|x| match x.listener_type {
                ListenerType::HTTP => {
                    ports.port = Some(x.port);
                }
                ListenerType::SOCKS5 => {
                    ports.socks_port = Some(x.port);
                }
            });

        ports
    }
}
