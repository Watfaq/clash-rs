use crate::{
    common::auth::ThreadSafeAuthenticator,
    config::listener::InboundOpts,
    proxy::{
        http::HttpInbound, inbound::InboundHandlerTrait, mixed::MixedInbound,
        socks::inbound::SocksInbound, tunnel::TunnelInbound,
    },
};

#[cfg(all(target_os = "linux", feature = "redir"))]
use crate::proxy::redir::RedirInbound;
#[cfg(all(target_os = "linux", feature = "tproxy"))]
use crate::proxy::tproxy::TproxyInbound;

use crate::Dispatcher;
use futures::future::BoxFuture;
use tracing::{error, info, warn};

#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks::inbound::{
    InboundOptions, SharedUserStats, ShadowsocksInbound,
};
use std::sync::Arc;

/// Returns the listener futures AND, for inbound types that support per-user
/// traffic stats, a `SharedUserStats` Arc (keyed by user name, plus
/// `STAT_KEY_TOTAL`).  The caller is responsible for storing the stats
/// somewhere accessible (e.g. `InboundManager::listener_stats`).
pub(crate) fn build_network_listeners(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> (
    Option<Vec<BoxFuture<'static, Result<(), crate::Error>>>>,
    Option<SharedUserStats>,
) {
    let name = &inbound_opts.common_opts().name;
    let addr = inbound_opts.common_opts().listen.0;
    let port = inbound_opts.common_opts().port;

    let mut stats_out: Option<SharedUserStats> = None;

    let runners = if let Some(handler) =
        build_handler(inbound_opts, dispatcher, authenticator, &mut stats_out)
    {
        let mut runners: Vec<BoxFuture<'static, Result<(), crate::Error>>> =
            Vec::new();

        if handler.handle_tcp() {
            let tcp_listener = handler.clone();

            let name = name.clone();
            runners.push(Box::pin(async move {
                info!("{} TCP listening at: {}:{}", name, addr, port,);
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
            let udp_listener = handler.clone();
            let name = name.clone();
            runners.push(Box::pin(async move {
                info!("{} UDP listening at: {}:{}", name, addr, port,);
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
            None
        } else {
            Some(runners)
        }
    } else {
        None
    };

    (runners, stats_out)
}

fn build_handler(
    listener: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    #[allow(unused_variables)] stats_out: &mut Option<SharedUserStats>,
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
        #[cfg(feature = "tproxy")]
        InboundOpts::TProxy {
            #[cfg(target_os = "linux")]
            common_opts,
            ..
        } => {
            #[cfg(target_os = "linux")]
            {
                Some(Arc::new(TproxyInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    dispatcher,
                    fw_mark,
                )))
            }

            #[cfg(not(target_os = "linux"))]
            {
                warn!("tproxy is not supported on this platform");
                None
            }
        }
        #[cfg(feature = "redir")]
        InboundOpts::Redir {
            #[cfg(target_os = "linux")]
            common_opts,
            ..
        } => {
            #[cfg(target_os = "linux")]
            {
                Some(Arc::new(RedirInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    dispatcher,
                    fw_mark,
                )))
            }
            #[cfg(not(target_os = "linux"))]
            {
                warn!("redir is not supported on this platform");
                None
            }
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
        #[cfg(feature = "shadowsocks")]
        InboundOpts::Shadowsocks {
            common_opts,
            udp,
            cipher,
            password,
            users,
        } => {
            let inbound = ShadowsocksInbound::new(InboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                udp: *udp,
                cipher: cipher.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                authenticator,
                fw_mark: common_opts.fw_mark,
                users: users.clone(),
            });
            // Capture the shared stats Arc before we lose the concrete type.
            *stats_out = Some(inbound.user_traffic_stats.clone());
            Some(Arc::new(inbound))
        }
    }
}
