use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, task::JoinHandle};

use crate::{
    app::{
        dispatcher::Dispatcher, inbound::network_listener::build_network_listeners,
    },
    common::auth::ThreadSafeAuthenticator,
    config::internal::{config::BindAddress, listener::InboundOpts},
    runner::Runner,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tracing::{info, warn};

/// Legacy ports configuration for inbounds.
/// Newer inbounds have their own port configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

pub struct InboundManager {
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,

    /// Inbound options for each inbound type -> listening Task
    inbound_handlers: RwLock<HashMap<InboundOpts, Option<JoinHandle<()>>>>,

    cancellation_token: tokio_util::sync::CancellationToken,
}

impl Runner for InboundManager {
    fn run(&mut self) -> BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move {
            self.start_all_listeners().await;
            Ok(())
        })
    }

    fn shutdown(&mut self) -> BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move {
            self.cancellation_token.cancel();
            Ok(())
        })
    }

    fn join(&mut self) -> BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move { self.join_all_listeners().await })
    }
}
impl InboundManager {
    pub async fn new(
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        inbounds_opt: HashSet<InboundOpts>,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            inbound_handlers: RwLock::new(
                inbounds_opt.into_iter().map(|opts| (opts, None)).collect(),
            ),
            dispatcher,
            authenticator,
            cancellation_token: cancellation_token
                .unwrap_or_else(|| tokio_util::sync::CancellationToken::new()),
        }
    }

    async fn start_all_listeners(&self) {
        for (opts, handler) in self.inbound_handlers.write().await.iter_mut() {
            let cancellation_token = self.cancellation_token.clone();
            let name = opts.common_opts().name.clone();
            *handler = build_network_listeners(
                opts,
                self.dispatcher.clone(),
                self.authenticator.clone(),
            )
            .map(|r| {
                tokio::spawn(async move {
                    tokio::select! {
                        _ = futures::future::join_all(r) => {
                            warn!("Inbound handler {} has exited", name);
                        },
                        _ = cancellation_token.cancelled() => {
                            info!("Inbound handler {} is closed", name);
                        },
                    }
                })
            });
        }
    }

    async fn stop_all_listeners(&self) {
        for (opt, l) in self.inbound_handlers.write().await.iter_mut() {
            if let Some(handler) = l.take() {
                warn!("Shutting down inbound handler: {}", opt.common_opts().name);
                handler.abort();
            }
            *l = None;
        }
    }

    async fn join_all_listeners(&self) -> Result<(), crate::Error> {
        let mut last_join_error = None;
        for (opt, l) in self.inbound_handlers.write().await.iter_mut() {
            if let Some(handler) = l.take() {
                warn!("Shutting down inbound handler: {}", opt.common_opts().name);
                handler.await.unwrap_or_else(|e| {
                    warn!(
                        "Inbound handler {} shutdown with error: {}",
                        opt.common_opts().name,
                        e
                    );
                    last_join_error = Some(e);
                });
            }
        }
        last_join_error
            .map(|e| Err(std::io::Error::new(std::io::ErrorKind::Other, e).into()))
            .unwrap_or(Ok(()))
    }

    // RESTFUL API handlers below
    pub async fn restart(&self) -> Result<(), crate::Error> {
        self.stop_all_listeners().await;
        self.start_all_listeners().await;
        Ok(())
    }

    pub async fn get_ports(&self) -> Ports {
        let mut ports = Ports::default();
        let guard = self.inbound_handlers.read().await;
        for opts in guard.keys() {
            match &opts {
                InboundOpts::Http { common_opts } => {
                    ports.port = Some(common_opts.port)
                }
                InboundOpts::Socks { common_opts, .. } => {
                    ports.socks_port = Some(common_opts.port)
                }
                InboundOpts::Mixed { common_opts, .. } => {
                    ports.mixed_port = Some(common_opts.port)
                }
                #[cfg(feature = "tproxy")]
                InboundOpts::TProxy { common_opts, .. } => {
                    ports.tproxy_port = Some(common_opts.port)
                }
                #[cfg(feature = "redir")]
                InboundOpts::Redir { common_opts } => {
                    ports.redir_port = Some(common_opts.port)
                }
                _ => {}
            }
        }
        ports
    }

    pub async fn get_allow_lan(&self) -> bool {
        let guard = self.inbound_handlers.read().await;
        if let Some((opts, _)) = guard.iter().next() {
            opts.common_opts().allow_lan
        } else {
            false
        }
    }

    pub async fn set_allow_lan(&self, allow_lan: bool) {
        let mut guard = self.inbound_handlers.write().await;
        let new_map = guard
            .drain()
            .map(|(mut opts, handler)| {
                opts.common_opts_mut().allow_lan = allow_lan;
                (opts, handler)
            })
            .collect::<HashMap<_, _>>();
        *guard = new_map;
    }

    pub async fn get_bind_address(&self) -> BindAddress {
        let guard = self.inbound_handlers.read().await;
        if let Some((opts, _)) = guard.iter().next() {
            opts.common_opts().listen
        } else {
            BindAddress::default()
        }
    }

    pub async fn set_bind_address(&self, bind_address: BindAddress) {
        let mut guard = self.inbound_handlers.write().await;
        let new_map = guard
            .drain()
            .map(|(mut opts, handler)| {
                opts.common_opts_mut().listen = bind_address;
                (opts, handler)
            })
            .collect::<HashMap<_, _>>();
        *guard = new_map;
    }

    pub async fn change_ports(&self, ports: Ports) {
        let mut guard = self.inbound_handlers.write().await;

        let listeners: HashMap<InboundOpts, Option<_>> = guard
            .extract_if(|opts, _| match &opts {
                InboundOpts::Http { common_opts } => {
                    ports.port.is_some() && Some(common_opts.port) == ports.port
                }
                InboundOpts::Socks { common_opts, .. } => {
                    ports.socks_port.is_some()
                        && Some(common_opts.port) == ports.socks_port
                }
                InboundOpts::Mixed { common_opts, .. } => {
                    ports.mixed_port.is_some()
                        && Some(common_opts.port) == ports.mixed_port
                }
                #[cfg(feature = "tproxy")]
                InboundOpts::TProxy { common_opts, .. } => {
                    ports.tproxy_port.is_some()
                        && Some(common_opts.port) == ports.tproxy_port
                }
                #[cfg(feature = "redir")]
                InboundOpts::Redir { common_opts } => {
                    ports.redir_port.is_some()
                        && Some(common_opts.port) == ports.redir_port
                }
                _ => false,
            })
            .collect();

        for (mut opts, handle) in listeners {
            opts.common_opts_mut().port = match &opts {
                InboundOpts::Http { common_opts } => {
                    ports.port.unwrap_or(common_opts.port)
                }
                InboundOpts::Socks { common_opts, .. } => {
                    ports.socks_port.unwrap_or(common_opts.port)
                }
                InboundOpts::Mixed { common_opts, .. } => {
                    ports.mixed_port.unwrap_or(common_opts.port)
                }
                #[cfg(feature = "tproxy")]
                InboundOpts::TProxy { common_opts, .. } => {
                    ports.tproxy_port.unwrap_or(common_opts.port)
                }
                #[cfg(feature = "redir")]
                InboundOpts::Redir { common_opts } => {
                    ports.redir_port.unwrap_or(common_opts.port)
                }
                _ => continue,
            };

            guard.insert(opts, handle);
        }
    }
}
