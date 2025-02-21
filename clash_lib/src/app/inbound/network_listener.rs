use crate::{
    common::auth::ThreadSafeAuthenticator, config::internal::config::BindAddress,
};

use crate::proxy::{AnyInboundListener, http, mixed, socks};

#[cfg(target_os = "linux")]
use crate::proxy::tproxy;

use crate::{Dispatcher, Error, Runner, proxy::utils::Interface};
use futures::FutureExt;
use network_interface::{Addr, NetworkInterfaceConfig};
use tracing::{info, warn};

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum ListenerType {
    Http,
    Socks5,
    Mixed,
    Tproxy,
}

pub struct NetworkInboundListener {
    pub name: String,
    pub bind_addr: BindAddress,
    pub port: u16,
    pub listener_type: ListenerType,
    pub dispatcher: Arc<Dispatcher>,
    pub authenticator: ThreadSafeAuthenticator,
}

impl NetworkInboundListener {
    pub fn listen(&self) -> Result<Vec<Runner>, Error> {
        let mut runners = Vec::<Runner>::new();

        match &self.bind_addr {
            BindAddress::Any => {
                #[cfg(target_os = "ios")]
                {
                    let all_ifaces = network_interface::NetworkInterface::show()
                        .expect("list interfaces");

                    for iface in all_ifaces.into_iter() {
                        let ip = iface
                            .addr
                            .into_iter()
                            .filter_map(|x| match x {
                                Addr::V4(v4) => {
                                    if v4.ip.is_unspecified()
                                        || v4.ip.is_link_local()
                                        || v4.ip.is_multicast()
                                    {
                                        None
                                    } else {
                                        Some(v4.ip)
                                    }
                                }
                                Addr::V6(_) => None,
                            })
                            .next();

                        if !ip.is_some() {
                            continue;
                        }

                        self.build_and_insert_listener(&mut runners, ip.unwrap());
                    }
                }
                #[cfg(not(target_os = "ios"))]
                {
                    let ip = "0.0.0.0".parse().expect("must parse");
                    self.build_and_insert_listener(&mut runners, ip);
                }
            }
            BindAddress::One(iface) => match iface {
                Interface::IpAddr(ip) => match ip {
                    IpAddr::V4(ip) => {
                        self.build_and_insert_listener(&mut runners, *ip)
                    }
                    IpAddr::V6(_) => unreachable!("unsupported listening v6"),
                },
                Interface::Name(iface) => {
                    let ip = network_interface::NetworkInterface::show()
                        .expect("list interfaces")
                        .into_iter()
                        .filter(|x| &x.name == iface)
                        .flat_map(|x| x.addr)
                        .map(|x| match x {
                            Addr::V4(v4) => v4.ip,
                            Addr::V6(_) => unreachable!(),
                        })
                        .find(|x| {
                            !x.is_unspecified()
                                && !x.is_link_local()
                                && !x.is_multicast()
                        })
                        .expect("no valid ip");

                    self.build_and_insert_listener(&mut runners, ip);
                }
            },
        };

        Ok(runners)
    }

    fn build_and_insert_listener(&self, runners: &mut Vec<Runner>, ip: Ipv4Addr) {
        let listener: AnyInboundListener = match self.listener_type {
            ListenerType::Http => Arc::new(http::Listener::new(
                (ip, self.port).into(),
                self.dispatcher.clone(),
                self.authenticator.clone(),
            )),
            ListenerType::Socks5 => Arc::new(socks::Listener::new(
                (ip, self.port).into(),
                self.dispatcher.clone(),
                self.authenticator.clone(),
            )),
            ListenerType::Mixed => Arc::new(mixed::Listener::new(
                (ip, self.port).into(),
                self.dispatcher.clone(),
                self.authenticator.clone(),
            )),
            ListenerType::Tproxy => {
                #[cfg(target_os = "linux")]
                {
                    Arc::new(tproxy::Listener::new(
                        (ip, self.port).into(),
                        self.dispatcher.clone(),
                    ))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    warn!("tproxy is not supported on this platform");
                    return;
                }
            }
        };

        if listener.handle_tcp() {
            let listener_type = self.listener_type.clone();
            info!("{} TCP listening at: {}:{}", self.name, ip, self.port);

            let tcp_listener = listener.clone();
            runners.push(
                async move {
                    tcp_listener.listen_tcp().await.map_err(|e| {
                        warn!(
                            "handler of {:?} tcp listen failed: {}",
                            listener_type, e
                        );
                        e.into()
                    })
                }
                .boxed(),
            );
        }

        if listener.handle_udp() {
            info!("{} UDP listening at: {}:{}", self.name, ip, self.port);
            let udp_listener = listener.clone();
            runners.push(
                async move {
                    udp_listener.listen_udp().await.map_err(|e| {
                        warn!("handler udp listen failed: {}", e);
                        e.into()
                    })
                }
                .boxed(),
            );
        }
    }
}
