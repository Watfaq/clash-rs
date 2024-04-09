use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::app::dispatcher::Dispatcher;
use crate::app::inbound::network_listener::{ListenerType, NetworkInboundListener};
use crate::common::auth::ThreadSafeAuthenticator;
use crate::config::internal::config::{BindAddress, Inbound};
use crate::{Error, Runner};
use std::collections::HashMap;
use std::sync::Arc;

pub struct InboundManager {
    network_listeners: HashMap<ListenerType, NetworkInboundListener>,
    dispatcher: Arc<Dispatcher>,
    bind_address: BindAddress,
    authenticator: ThreadSafeAuthenticator,
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
    pub fn new(
        inbound: Inbound,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
    ) -> Result<Self, Error> {
        let network_listeners = HashMap::new();

        let mut s = Self {
            network_listeners,
            dispatcher,
            bind_address: inbound.bind_address,
            authenticator,
        };

        let ports = Ports {
            port: inbound.port,
            socks_port: inbound.socks_port,
            redir_port: inbound.redir_port,
            tproxy_port: inbound.tproxy_port,
            mixed_port: inbound.mixed_port,
        };

        s.rebuild_listeners(ports);
        Ok(s)
    }

    pub fn get_runner(&self) -> Result<Runner, Error> {
        let mut runners = Vec::new();
        for r in self.network_listeners.values() {
            runners.append(&mut r.listen()?);
        }

        Ok(Box::pin(async move {
            futures::future::select_all(runners).await.0
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
                ListenerType::Http => {
                    ports.port = Some(x.port);
                }
                ListenerType::Socks5 => {
                    ports.socks_port = Some(x.port);
                }
                ListenerType::Mixed => {
                    ports.mixed_port = Some(x.port);
                }
                ListenerType::TProxy => {
                    ports.tproxy_port = Some(x.port);
                }
            });

        ports
    }

    pub fn rebuild_listeners(&mut self, ports: Ports) {
        let mut network_listeners = HashMap::new();
        if let Some(http_port) = ports.port {
            network_listeners.insert(
                ListenerType::Http,
                NetworkInboundListener {
                    name: "HTTP".to_string(),
                    bind_addr: self.bind_address.clone(),
                    port: http_port,
                    listener_type: ListenerType::Http,
                    dispatcher: self.dispatcher.clone(),
                    authenticator: self.authenticator.clone(),
                },
            );
        }

        if let Some(socks_port) = ports.socks_port {
            network_listeners.insert(
                ListenerType::Socks5,
                NetworkInboundListener {
                    name: "SOCKS5".to_string(),
                    bind_addr: self.bind_address.clone(),
                    port: socks_port,
                    listener_type: ListenerType::Socks5,
                    dispatcher: self.dispatcher.clone(),
                    authenticator: self.authenticator.clone(),
                },
            );
        }

        if let Some(mixed_port) = ports.mixed_port {
            network_listeners.insert(
                ListenerType::Mixed,
                NetworkInboundListener {
                    name: "Mixed".to_string(),
                    bind_addr: self.bind_address.clone(),
                    port: mixed_port,
                    listener_type: ListenerType::Mixed,
                    dispatcher: self.dispatcher.clone(),
                    authenticator: self.authenticator.clone(),
                },
            );
        }

        if let Some(tproxy_port) = ports.tproxy_port {
            network_listeners.insert(
                ListenerType::TProxy,
                NetworkInboundListener {
                    name: "TProxy".to_string(),
                    bind_addr: self.bind_address.clone(),
                    port: tproxy_port,
                    listener_type: ListenerType::TProxy,
                    dispatcher: self.dispatcher.clone(),
                    authenticator: self.authenticator.clone(),
                },
            );
        }

        self.network_listeners = network_listeners;
    }
}
