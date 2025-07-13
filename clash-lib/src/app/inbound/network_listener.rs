#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks::inbound::{InboundOptions, ShadowsocksInbound};
#[cfg(target_os = "linux")]
use crate::proxy::tproxy::TproxyInbound;
#[cfg(all(target_os = "linux", feature = "tproxy"))]
use crate::proxy::tproxy::TproxyInbound;
use crate::{
    Dispatcher, Runner,
    common::auth::ThreadSafeAuthenticator,
    config::{config::BindAddress, listener::InboundOpts},
    proxy::{
        http::HttpInbound, inbound::InboundHandlerTrait, mixed::MixedInbound,
        socks::inbound::SocksInbound, tunnel::TunnelInbound,
    },
};
use network_interface::{Addr, NetworkInterfaceConfig};
use std::{net::IpAddr, sync::Arc};
use tracing::{error, info, warn};

pub(crate) fn build_network_listeners(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Option<Vec<Runner>> {
    let name = &inbound_opts.common_opts().name;
    let addr = inbound_opts.common_opts().listen.0;
    let port = inbound_opts.common_opts().port;

    if cfg!(target_os = "ios") {
        if addr.is_unspecified() {
            let mut runners: Vec<Runner> = Vec::new();
            let all_ifaces = network_interface::NetworkInterface::show()
                .inspect_err(|e| {
                    error!("failed to get network interfaces: {e}");
                })
                .ok()?;
            let all_available_addrs = all_ifaces
                .into_iter()
                .filter_map(|iface| {
                    iface.addr.into_iter().find_map(|ip| match ip {
                        Addr::V4(v4) => {
                            if !(v4.ip.is_unspecified()
                                || v4.ip.is_link_local()
                                || v4.ip.is_multicast())
                            {
                                Some(v4.ip)
                            } else {
                                None
                            }
                        }
                        Addr::V6(_) => None,
                    })
                })
                .collect::<Vec<_>>();

            for addr in all_available_addrs {
                info!("{} listening at: {}:{}", name, addr, port);
                let mut inbound_opts = inbound_opts.clone();
                inbound_opts.common_opts_mut().listen = BindAddress(addr.into());
                let handler = build_handler(
                    &inbound_opts,
                    dispatcher.clone(),
                    authenticator.clone(),
                )?;
                let name = name.to_string();
                if let Some(r) =
                    get_runners_for_handler(handler, name, addr.into(), port)
                {
                    runners.extend(r);
                }
            }

            return if runners.is_empty() {
                warn!("no listener for {}", name);
                None
            } else {
                Some(runners)
            };
        }
    }

    if let Some(handler) = build_handler(inbound_opts, dispatcher, authenticator) {
        get_runners_for_handler(handler, name.to_string(), addr, port)
    } else {
        None
    }
}

fn get_runners_for_handler(
    handler: Arc<dyn InboundHandlerTrait>,
    name: String,
    addr: IpAddr,
    port: u16,
) -> Option<Vec<Runner>> {
    let mut runners: Vec<Runner> = Vec::new();

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
        #[cfg(feature = "shadowsocks")]
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
