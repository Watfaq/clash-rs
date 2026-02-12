use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::{
    Error,
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::config::TunConfig,
    proxy::tun::{datagram::handle_inbound_datagram, stream::handle_inbound_stream},
    runner::Runner,
};

#[derive(Default)]
struct TunInitializationConfig {
    fd: Option<u32>,
    tun_name: Option<String>,
    #[cfg(target_os = "windows")]
    guid: Option<u128>,
}

pub struct TunRunner {
    cfg: TunConfig,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    cancellation_token: CancellationToken,
}

impl TunRunner {
    pub fn new(
        cfg: TunConfig,
        dispatcher: Arc<Dispatcher>,
        resolver: ThreadSafeDNSResolver,
        cancellation_token: Option<CancellationToken>,
    ) -> Result<TunRunner, Error> {
        Ok(Self {
            cfg,
            dispatcher,
            resolver,
            cancellation_token: cancellation_token
                .unwrap_or_else(CancellationToken::new),
        })
    }

    fn new_internal(
        &self,
    ) -> Result<
        (
            tun_rs::AsyncDevice,
            watfaq_netstack::NetStack,
            watfaq_netstack::TcpListener,
            watfaq_netstack::UdpSocket,
        ),
        Error,
    > {
        let mut tun_init_config = TunInitializationConfig::default();
        match Url::parse(&self.cfg.device_id) {
            Ok(u) => match u.scheme() {
                "fd" => {
                    let fd = u
                        .host()
                        .expect("tun fd must be provided")
                        .to_string()
                        .parse()
                        .map_err(|x| Error::InvalidConfig(format!("tun fd {x}")))?;
                    tun_init_config.fd = Some(fd);
                }
                "dev" => {
                    let dev =
                        u.host().expect("tun dev must be provided").to_string();
                    if cfg!(target_os = "macos") && !dev.starts_with("utun") {
                        return Err(Error::InvalidConfig(format!(
                            "invalid device id: {}. tun name must be utunX",
                            self.cfg.device_id
                        )));
                    }
                    tun_init_config.tun_name = Some(dev);
                    #[cfg(target_os = "windows")]
                    {
                        let guid = u.query_pairs().find(|(k, _)| k == "guid");
                        if let Some((_, v)) = guid {
                            let guid = uuid::Uuid::parse_str(&v).map_err(|x| {
                                Error::InvalidConfig(format!("invalid guid: {x}"))
                            })?;
                            tun_init_config.guid = Some(guid.as_u128());
                        }
                    }
                }
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "invalid device id: {}",
                        self.cfg.device_id
                    )));
                }
            },
            Err(_) => {
                if cfg!(target_os = "macos")
                    && !&self.cfg.device_id.starts_with("utun")
                {
                    return Err(Error::InvalidConfig(format!(
                        "invalid device id: {}. tun name must be utunX",
                        self.cfg.device_id
                    )));
                }
                tun_init_config.tun_name = Some(self.cfg.device_id.clone());
            }
        };

        let tun = if let Some(fd) = tun_init_config.fd {
            #[cfg(target_family = "unix")]
            {
                info!("tun started with fd {}", fd);
                unsafe { tun_rs::AsyncDevice::from_fd(fd as _)? }
            }

            #[cfg(not(target_family = "unix"))]
            {
                return Err(Error::InvalidConfig(format!(
                    "tun fd({fd}) is only supported on Unix-like systems"
                )));
            }
        } else {
            #[cfg(not(any(target_os = "ios", target_os = "android")))]
            {
                use crate::proxy::tun::routes::maybe_add_routes;
                use network_interface::NetworkInterfaceConfig;
                use tun_rs::DeviceBuilder;

                let tun_name =
                    tun_init_config.tun_name.expect("tun name must be provided");
                let tun_exist = network_interface::NetworkInterface::show()
                    .map(|ifs| ifs.into_iter().any(|x| x.name == tun_name))
                    .unwrap_or_default();

                if tun_exist {
                    info!("tun device {} already exists, using it.", &tun_name);
                } else {
                    info!("tun device {} does not exist, creating.", &tun_name);
                }

                let mut tun_builder = DeviceBuilder::new();
                tun_builder = tun_builder.name(&tun_name).mtu(
                    self.cfg.mtu.unwrap_or(if cfg!(windows) {
                        65535u16
                    } else {
                        1500u16
                    }),
                );

                if !tun_exist {
                    debug!("setting tun ipv4 addr: {:?}", self.cfg.gateway);
                    tun_builder = tun_builder.ipv4(
                        self.cfg.gateway.addr(),
                        self.cfg.gateway.netmask(),
                        None,
                    );

                    if let Some(gateway_v6) = self.cfg.gateway_v6 {
                        debug!("setting tun ipv6 addr: {:?}", self.cfg.gateway_v6);
                        tun_builder = tun_builder
                            .ipv6(gateway_v6.addr(), gateway_v6.netmask());
                    }
                }
                #[cfg(target_os = "windows")]
                if let Some(guid) = tun_init_config.guid {
                    tun_builder = tun_builder.device_guid(guid);
                }

                let dev = tun_builder.build_async()?;

                if !tun_exist {
                    info!("setting up routes for tun {}", &tun_name);
                    maybe_add_routes(&self.cfg, &tun_name)?;
                } else {
                    info!("skipping route setup for existing tun {}", &tun_name);
                }

                dev
            }
            #[cfg(any(target_os = "ios", target_os = "android"))]
            {
                return Err(Error::InvalidConfig(
                    "only fd is supported on mobile platforms".to_string(),
                ));
            }
        };

        let (stack, tcp_listener, udp_socket) = watfaq_netstack::NetStack::new();
        Ok((tun, stack, tcp_listener, udp_socket))
    }
}

impl Runner for TunRunner {
    fn run(&self) -> futures::future::BoxFuture<'_, Result<(), crate::Error>> {
        let so_mark = self.cfg.so_mark;
        let dispatcher = self.dispatcher.clone();
        let resolver = self.resolver.clone();
        let dns_hijack = self.cfg.dns_hijack;
        let cancellation_token = self.cancellation_token.clone();

        // Call new_internal outside the async move closure
        let internal_result = self.new_internal();

        Box::pin(async move {
            let (tun, stack, mut tcp_listener, udp_socket) = internal_result?;

            let framed = tun_rs::async_framed::DeviceFramed::new(
                tun,
                tun_rs::async_framed::BytesCodec::new(),
            );

            let (mut tun_sink, mut tun_stream) = framed.split::<bytes::Bytes>();
            let (mut stack_sink, mut stack_stream) = stack.split();

            // dispatcher -> stack -> tun

            let mut fut_dispatcher_tun = async || {
                while let Some(pkt) = stack_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if let Err(e) = tun_sink.send(pkt.into_bytes()).await {
                                error!("failed to send pkt to tun: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("tun stack error: {}", e);
                            break;
                        }
                    }
                }

                Err(Error::Operation("tun stopped unexpectedly 0".to_string()))
            };

            // tun -> stack -> dispatcher
            let mut fut_tun_dispatcher = async || {
                while let Some(pkt) = tun_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if let Err(e) = stack_sink
                                .send(watfaq_netstack::Packet::new(pkt))
                                .await
                            {
                                error!("failed to send pkt to stack: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("tun stream error: {}", e);
                            break;
                        }
                    }
                }

                Err(Error::Operation("tun stopped unexpectedly 1".to_string()))
            };

            let dsp = dispatcher.clone();
            let mut fut_tcp_dispatch = async || {
                while let Some(stream) = tcp_listener.next().await {
                    debug!(
                        "new tun TCP connection: {} -> {}",
                        stream.local_addr(),
                        stream.remote_addr()
                    );

                    tokio::spawn(handle_inbound_stream(
                        stream,
                        dsp.clone(),
                        so_mark,
                    ));
                }

                Err(Error::Operation("tun stopped unexpectedly 2".to_string()))
            };
            let fut_udp_dispatch = async || {
                handle_inbound_datagram(
                    udp_socket,
                    dispatcher.clone(),
                    resolver.clone(),
                    so_mark,
                    dns_hijack,
                )
                .await;
                Err(Error::Operation("tun stopped unexpectedly 3".to_string()))
            };

            tokio::select! {
                res = fut_dispatcher_tun() => res,
                res = fut_tun_dispatcher() => res,
                res = fut_tcp_dispatch() => res,
                res = fut_udp_dispatch() => res,
                _ = cancellation_token.cancelled() => {
                    info!("tun runner is closed");
                    Ok(())
                },
            }
        })
    }

    fn shutdown(&self) -> futures::future::BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            info!("shutting down tun runner");
            self.cancellation_token.cancel();
            Ok(())
        })
    }

    fn join(&self) -> futures::future::BoxFuture<'_, Result<(), Error>> {
        let enable = self.cfg.enable;
        Box::pin(async move {
            if !enable {
                info!("tun is disabled, nothing to join");
                return Ok(());
            }

            warn!("cleaning up routes");
            // Note: cannot clean up routes here as it requires &TunConfig
            // TODO: ideally join all the tasks spawned by tun runner here

            Ok(())
        })
    }
}
