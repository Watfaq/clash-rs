use crate::{
    Runner,
    common::auth::ThreadSafeAuthenticator,
    config::listener::InboundOpts,
    proxy::{
        http::HttpInbound, inbound::InboundHandlerTrait, mixed::MixedInbound,
        socks::SocksInbound, tunnel::TunnelInbound,
    },
};

#[cfg(target_os = "linux")]
use crate::proxy::tproxy::TproxyInbound;

use crate::Dispatcher;
use tracing::{error, info, warn};

use std::sync::Arc;

pub struct NetworkInboundHandler {
    pub name: String,
    pub listener: InboundOpts,
    pub dispatcher: Arc<Dispatcher>,
    pub authenticator: ThreadSafeAuthenticator,
    pub fw_mark: Option<u32>,
}

impl NetworkInboundHandler {
    pub fn listen(&self) -> Option<Vec<Runner>> {
        if let Some(handler) = self.build_and_insert_listener() {
            let mut runners: Vec<Runner> = Vec::new();

            if handler.handle_tcp() {
                info!(
                    "{} TCP listening at: {}:{}",
                    self.name,
                    self.listener.common_opts().listen.0,
                    self.listener.common_opts().port
                );

                let tcp_listener = handler.clone();

                let name = self.name.clone();
                runners.push(Box::pin(async move {
                    tcp_listener
                        .listen_tcp()
                        .await
                        .inspect_err(|x| {
                            error!("handler {} tcp listen failed: {x}", name);
                        })
                        .map_err(|e| e.into())
                }));
            }

            if handler.handle_udp() {
                info!(
                    "{} UDP listening at: {}:{}",
                    self.name,
                    self.listener.common_opts().listen.0,
                    self.listener.common_opts().port
                );
                let udp_listener = handler.clone();
                let name = self.name.clone();
                runners.push(Box::pin(async move {
                    udp_listener
                        .listen_udp()
                        .await
                        .inspect_err(|x| {
                            error!("handler {} udp listen failed: {x}", name);
                        })
                        .map_err(|e| e.into())
                }));
            }

            if runners.is_empty() {
                warn!("no listener for {}", self.name);
                return None;
            }
            Some(runners)
        } else {
            None
        }
    }

    fn build_and_insert_listener(&self) -> Option<Arc<dyn InboundHandlerTrait>> {
        match &self.listener {
            InboundOpts::Http { common_opts, .. } => {
                Some(Arc::new(HttpInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    self.dispatcher.clone(),
                    self.authenticator.clone(),
                    self.fw_mark,
                )) as _)
            }

            InboundOpts::Socks { common_opts, .. } => {
                Some(Arc::new(SocksInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    self.dispatcher.clone(),
                    self.authenticator.clone(),
                    self.fw_mark,
                )) as _)
            }
            InboundOpts::Mixed { common_opts, .. } => {
                Some(Arc::new(MixedInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    self.dispatcher.clone(),
                    self.authenticator.clone(),
                    self.fw_mark,
                )) as _)
            }
            InboundOpts::TProxy {
                #[cfg(target_os = "linux")]
                common_opts,
                ..
            } => {
                #[cfg(target_os = "linux")]
                {
                    Some(Box::new(TproxyInbound::new(
                        (common_opts.listen.0, common_opts.port).into(),
                        common_opts.allow_lan,
                        self.dispatcher.clone(),
                        self.fw_mark,
                    )) as _)
                }

                #[cfg(not(target_os = "linux"))]
                {
                    warn!("tproxy is not supported on this platform");
                    None
                }
            }
            InboundOpts::Redir { .. } => {
                warn!("redir is not implemented yet");
                None
            }
            InboundOpts::Tunnel {
                common_opts,
                network,
                target,
            } => TunnelInbound::new(
                (common_opts.listen.0, common_opts.port).into(),
                self.dispatcher.clone(),
                network.clone(),
                target.clone(),
                self.fw_mark,
            )
            .inspect_err(|x| {
                warn!("tunnel inbound handler failed to create: {x}");
            })
            .map(|x| Arc::new(x) as _)
            .ok(),
        }
    }
}
