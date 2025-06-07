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

use crate::proxy::shadowsocks::inbound::{InboundOptions, ShadowsocksInbound};
use std::sync::Arc;

pub(crate) fn build_network_listeners(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Option<Vec<Runner>> {
    let name = &inbound_opts.common_opts().name;
    let addr = inbound_opts.common_opts().listen.0;
    let port = inbound_opts.common_opts().port;

    if let Some(handler) = build_handler(inbound_opts, dispatcher, authenticator) {
        let mut runners: Vec<Runner> = Vec::new();

        if handler.handle_tcp() {
            info!("{} TCP listening at: {}:{}", name, addr, port,);

            let tcp_listener = handler.clone();

            let name = name.clone();
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
            info!("{} UDP listening at: {}:{}", name, addr, port,);
            let udp_listener = handler.clone();
            let name = name.clone();
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
            warn!("no listener for {}", name);
            return None;
        }
        Some(runners)
    } else {
        None
    }
}

fn build_handler(
    listener: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Option<Arc<dyn InboundHandlerTrait>> {
    let fw_mark = listener.common_opts().fw_mark;
    match listener {
        InboundOpts::Http { common_opts, .. } => Some(Arc::new(HttpInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),

        InboundOpts::Socks { common_opts, .. } => Some(Arc::new(SocksInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        InboundOpts::Mixed { common_opts, .. } => Some(Arc::new(MixedInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
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
                )))
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
            dispatcher,
            network.clone(),
            target.clone(),
            fw_mark,
        )
        .inspect_err(|x| {
            warn!("tunnel inbound handler failed to create: {x}");
        })
        .map(|x| Arc::new(x) as _)
        .ok(),
        InboundOpts::Shadowsocks {
            common_opts,
            udp,
            cipher,
            password,
        } => Some(Arc::new(ShadowsocksInbound::new(InboundOptions {
            addr: (common_opts.listen.0, common_opts.port).into(),
            password: password.clone(),
            udp: *udp,
            cipher: cipher.clone(),
            allow_lan: common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark: common_opts.fw_mark,
        }))),
    }
}
