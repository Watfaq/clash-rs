use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::app::dispatcher::Dispatcher;
use crate::app::inbound::network_listener::{ListenerType, NetworkInboundListener};
use crate::config::internal::config::{BindAddress, Inbound};
use crate::{Error, Runner};
use std::collections::HashMap;
use std::sync::Arc;

pub struct InboundManager {
    network_listeners: HashMap<String, NetworkInboundListener>,
    bind_address: BindAddress,
}

pub type ThreadSafeInboundManager = Arc<Mutex<InboundManager>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ports {
    pub port: Option<u16>,
    #[serde(rename = "socks-port")]
    pub socks_port: Option<u16>,
    #[serde(rename = "redir-port")]
    pub redir_port: Option<u16>,
    #[serde(rename = "tproxy-port")]
    pub tproxy_port: Option<u16>,
    #[serde(rename = "mixed-port")]
    pub mixed_port: Option<u16>,
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
                    bind_addr: inbound.bind_address.clone(),
                    port: socks_port,
                    listener_type: ListenerType::SOCKS5,
                    dispatcher: dispatcher.clone(),
                },
            );
        }

        Ok(Self {
            network_listeners,
            bind_address: inbound.bind_address,
        })
    }

    pub fn get_runner(&self) -> Result<Runner, Error> {
        let mut runners = Vec::new();
        for r in self.network_listeners.values() {
            runners.append(&mut r.listen()?);
        }

        Ok(Box::pin(async move {
            futures::future::join_all(runners).await;
        }))
    }

    /// API handlers below
    pub fn get_bind_address(&self) -> &BindAddress {
        &self.bind_address
    }

    pub fn set_bind_address(&mut self, bind_address: BindAddress) {
        self.bind_address = bind_address;
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

    pub fn rebuild_listeners(&mut self, ports: Ports) {
        let mut network_listeners = HashMap::new();
        if let Some(http_port) = ports.port {
            network_listeners.insert(
                "HTTP".to_string(),
                NetworkInboundListener {
                    name: "HTTP".to_string(),
                    bind_addr: self.bind_address.clone(),
                    port: http_port,
                    listener_type: ListenerType::HTTP,
                    dispatcher: self
                        .network_listeners
                        .get("HTTP")
                        .unwrap()
                        .dispatcher
                        .clone(),
                },
            );
        }

        if let Some(socks_port) = ports.socks_port {
            network_listeners.insert(
                "SOCKS5".to_string(),
                NetworkInboundListener {
                    name: "SOCKS5".to_string(),
                    bind_addr: self.bind_address.clone(),
                    port: socks_port,
                    listener_type: ListenerType::SOCKS5,
                    dispatcher: self
                        .network_listeners
                        .get("SOCKS5")
                        .unwrap()
                        .dispatcher
                        .clone(),
                },
            );
        }

        self.network_listeners = network_listeners;
    }
}
