use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{RwLock, oneshot},
    task::{JoinHandle, JoinSet},
};
use tracing::error;

use crate::{
    Result,
    app::{
        dispatcher::Dispatcher, inbound::network_listener::NetworkInboundHandler,
    },
    common::auth::ThreadSafeAuthenticator,
    config::internal::{config::BindAddress, listener::InboundOpts},
};
use std::{collections::HashMap, sync::Arc};

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

type TaskHandle = RwLock<Option<(JoinHandle<Result<()>>, oneshot::Sender<()>)>>;

pub struct InboundManager {
    dispatcher: Arc<Dispatcher>,
    bind_address: ArcSwap<BindAddress>,
    authenticator: ThreadSafeAuthenticator,

    inbounds_opt: RwLock<HashMap<String, InboundOpts>>,
    inbounds_handler: RwLock<HashMap<String, NetworkInboundHandler>>,

    task_handle: TaskHandle,
}

impl InboundManager {
    pub async fn new(
        bind_address: BindAddress,
        _authentication: Vec<String>, // TODO
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        inbounds_opt: HashMap<String, InboundOpts>,
    ) -> Result<Self> {
        let s = Self {
            inbounds_handler: HashMap::with_capacity(3).into(),
            dispatcher,
            bind_address: ArcSwap::new(bind_address.into()),
            authenticator,
            inbounds_opt: inbounds_opt.into(),
            task_handle: RwLock::new(None),
        };
        s.build_handlers().await;
        Ok(s)
    }

    pub async fn start(self: &Arc<Self>) {
        let mut guard = self.task_handle.write().await;
        if let Some((handle, signal)) = guard.take() {
            _ = signal.send(());
            handle.abort();
        }

        let v = self.clone();
        let (signal_tx, signal_rx) = oneshot::channel();
        let handle = tokio::spawn(async move { v.build_task(signal_rx).await });
        *guard = Some((handle, signal_tx));
    }

    // FIXME: This is not working if
    // 1. Inner nested spawned tasks.
    // 2. spawn_blocking
    pub async fn shutdown(&self) {
        if let Some((handle, signal)) = self.task_handle.write().await.take() {
            _ = signal.send(());
            handle.abort();
        }
    }

    pub async fn restart(self: &Arc<Self>) {
        self.build_handlers().await;
        self.start().await;
    }

    // Build `inbounds_handler` tasks
    async fn build_task(
        self: &Arc<Self>,
        mut signal: oneshot::Receiver<()>,
    ) -> Result<()> {
        let mut runners = JoinSet::new();
        for (_, handler) in self.inbounds_handler.read().await.iter() {
            handler.listen(&mut runners)?;
        }
        loop {
            tokio::select! {
                Some(result) = runners.join_next() => {
                    match result {
                        Ok(Err(e)) => error!("failed to start inbound listeners: {e:?}"),
                        Err(e) => {
                            if let Ok(reason) = e.try_into_panic() {
                                std::panic::resume_unwind(reason);
                            }
                        }
                        _ => {}
                    }
                }
                _ = &mut signal => {
                    runners.shutdown().await;
                    break;
                }
            }
        }
        Ok(())
    }

    // Sync `inbounds_handler` with `inbounds_opt`
    async fn build_handlers(&self) {
        let mut network_listeners = HashMap::with_capacity(3);
        let guard = self.inbounds_opt.read().await;
        for (name, inbound) in guard.iter() {
            network_listeners.insert(
                name.clone(),
                NetworkInboundHandler {
                    name: name.to_string(),
                    dispatcher: self.dispatcher.clone(),
                    authenticator: self.authenticator.clone(),
                    listener: inbound.clone(), // TODO use Arc
                },
            );
        }

        *self.inbounds_handler.write().await = network_listeners;
    }

    // RESTFUL API handlers below
    pub async fn get_ports(&self) -> Ports {
        let mut ports = Ports::default();
        let guard = self.inbounds_opt.read().await;
        for (_, opts) in guard.iter() {
            match &opts {
                InboundOpts::Http {
                    common_opts,
                    inherited,
                } => {
                    if *inherited {
                        ports.port = Some(common_opts.port)
                    }
                }
                InboundOpts::Socks {
                    common_opts,
                    inherited,
                    ..
                } => {
                    if *inherited {
                        ports.socks_port = Some(common_opts.port)
                    }
                }
                InboundOpts::Mixed {
                    common_opts,
                    inherited,
                    ..
                } => {
                    if *inherited {
                        ports.mixed_port = Some(common_opts.port)
                    }
                }
                InboundOpts::TProxy {
                    common_opts,
                    inherited,
                    ..
                } => {
                    if *inherited {
                        ports.tproxy_port = Some(common_opts.port)
                    }
                }
                InboundOpts::Redir {
                    common_opts,
                    inherited,
                } => {
                    if *inherited {
                        ports.redir_port = Some(common_opts.port)
                    }
                }
                _ => {}
            }
        }
        ports
    }

    pub fn get_bind_address(&self) -> BindAddress {
        **self.bind_address.load()
    }

    pub async fn set_bind_address(&self, bind_address: BindAddress) {
        self.bind_address.store(Arc::new(bind_address));
        let mut guard = self.inbounds_opt.write().await;
        for (_, opts) in guard.iter_mut() {
            if opts.inherited() {
                opts.common_opts_mut().listen = bind_address
            }
        }
    }

    pub async fn change_ports(&self, ports: Ports) {
        let mut guard = self.inbounds_opt.write().await;
        for (_, opts) in guard.iter_mut() {
            match &opts {
                InboundOpts::Http { inherited, .. } => {
                    if *inherited && let Some(port) = ports.port {
                        *opts.port_mut() = port
                    }
                }
                InboundOpts::Socks { inherited, .. } => {
                    if *inherited && let Some(port) = ports.socks_port {
                        *opts.port_mut() = port
                    }
                }
                InboundOpts::Mixed { inherited, .. } => {
                    if *inherited && let Some(port) = ports.mixed_port {
                        *opts.port_mut() = port
                    }
                }
                InboundOpts::TProxy { inherited, .. } => {
                    if *inherited && let Some(port) = ports.tproxy_port {
                        *opts.port_mut() = port
                    }
                }
                InboundOpts::Redir { inherited, .. } => {
                    if *inherited && let Some(port) = ports.redir_port {
                        *opts.port_mut() = port
                    }
                }
                _ => {}
            }
        }
    }
}
