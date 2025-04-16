use crate::{
    common::auth::ThreadSafeAuthenticator,
    config::listener::InboundOpts,
    proxy::{
        http::HttpInbound,
        inbound::{InboudHandler, InboundHandlerTrait as _},
        mixed::MixedInbound,
        socks::SocksInbound,
        tunnel::TunnelInbound,
    },
};

#[cfg(target_os = "linux")]
use crate::proxy::tproxy::TproxyInbound;

use crate::Dispatcher;
use tokio::task::JoinSet;
use tracing::{info, warn};

use std::sync::Arc;

pub struct NetworkInboundHandler {
    pub name: String,
    pub listener: InboundOpts,
    pub dispatcher: Arc<Dispatcher>,
    pub authenticator: ThreadSafeAuthenticator,
    pub allow_lan: bool,
}

impl NetworkInboundHandler {
    pub fn listen(
        &self,
        set: &mut JoinSet<Result<(), crate::Error>>,
    ) -> crate::Result<()> {
        self.build_and_insert_listener(set)
    }

    fn build_and_insert_listener(
        &self,
        set: &mut JoinSet<Result<(), crate::Error>>,
    ) -> crate::Result<()> {
        let handler: InboudHandler = match &self.listener {
            InboundOpts::Http { common_opts, .. } => HttpInbound::new(
                (common_opts.listen.0, common_opts.port).into(),
                common_opts.allow_lan.unwrap_or(self.allow_lan),
                self.dispatcher.clone(),
                self.authenticator.clone(),
            )
            .into(),
            InboundOpts::Socks { common_opts, .. } => SocksInbound::new(
                (common_opts.listen.0, common_opts.port).into(),
                common_opts.allow_lan.unwrap_or(self.allow_lan),
                self.dispatcher.clone(),
                self.authenticator.clone(),
            )
            .into(),
            InboundOpts::Mixed { common_opts, .. } => MixedInbound::new(
                (common_opts.listen.0, common_opts.port).into(),
                common_opts.allow_lan.unwrap_or(self.allow_lan),
                self.dispatcher.clone(),
                self.authenticator.clone(),
            )
            .into(),
            #[allow(unused)]
            InboundOpts::TProxy { common_opts, .. } => {
                #[cfg(target_os = "linux")]
                {
                    TproxyInbound::new(
                        (common_opts.listen.0, common_opts.port).into(),
                        common_opts.allow_lan.unwrap_or(self.allow_lan),
                        self.dispatcher.clone(),
                    )
                    .into()
                }

                #[cfg(not(target_os = "linux"))]
                {
                    warn!("tproxy is not supported on this platform");
                    return Ok(());
                }
            }
            InboundOpts::Redir { .. } => unimplemented!(),
            InboundOpts::Tunnel {
                common_opts,
                network,
                target,
            } => TunnelInbound::new(
                (common_opts.listen.0, common_opts.port).into(),
                self.dispatcher.clone(),
                network.clone(),
                target.clone(),
            )?
            .into(),
        };
        let handler = Arc::new(handler);
        if handler.handle_tcp() {
            info!(
                "{} TCP listening at: {}:{}",
                self.name,
                self.listener.common_opts().listen.0,
                self.listener.common_opts().port
            );

            let tcp_listener = handler.clone();

            let name = self.name.clone();
            set.spawn(async move {
                tcp_listener.listen_tcp().await.map_err(|e| {
                    warn!("handler {} tcp listen failed: {e}", name);
                    e.into()
                })
            });
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
            set.spawn(async move {
                udp_listener.listen_udp().await.map_err(|e| {
                    warn!("handler {} udp listen failed: {e}", name);
                    e.into()
                })
            });
        }
        Ok(())
    }
}
