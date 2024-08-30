use super::{datagram::TunDatagram, netstack};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use futures::{SinkExt, StreamExt};
use ipnet::IpNet;
use network_interface::NetworkInterfaceConfig;
use tracing::{debug, error, info, trace, warn};
use tun::{Device, TunPacket};
use url::Url;

use crate::{
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    common::errors::{map_io_error, new_io_error},
    config::internal::config::TunConfig,
    proxy::{
        datagram::UdpPacket,
        tun::routes::add_route,
        utils::{get_outbound_interface, OutboundInterface},
    },
    session::{Network, Session, SocksAddr, Type},
    Error, Runner,
};

async fn handle_inbound_stream(
    stream: netstack::TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
) {
    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source: local_addr,
        destination: remote_addr.into(),
        iface: get_outbound_interface()
            .map(|x| crate::proxy::utils::Interface::Name(x.name))
            .inspect(|x| {
                debug!(
                    "selecting outbound interface: {:?} for tun TCP connection",
                    x
                );
            }),
        ..Default::default()
    };

    debug!("new tun TCP session assigned: {}", sess);
    dispatcher.dispatch_stream(sess, stream).await;
}

async fn handle_inbound_datagram(
    socket: Box<netstack::UdpSocket>,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
) {
    let local_addr = socket.local_addr();
    // tun i/o

    let (ls, mut lr) = socket.split();
    let ls = Arc::new(ls);

    // dispatcher <-> tun communications
    let (l_tx, mut l_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

    // forward packets from tun to dispatcher
    let (d_tx, d_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

    // for dispatcher - the dispatcher would receive packets from this channel,
    // which is from the stack and send back packets to this channel, which
    // is to the tun
    let udp_stream = TunDatagram::new(l_tx, d_rx, local_addr);

    let sess = Session {
        network: Network::Udp,
        typ: Type::Tun,
        iface: get_outbound_interface()
            .map(|x| crate::proxy::utils::Interface::Name(x.name))
            .inspect(|x| {
                debug!("selecting outbound interface: {:?} for tun UDP traffic", x);
            }),

        ..Default::default()
    };

    let closer = dispatcher.dispatch_datagram(sess, Box::new(udp_stream));

    // dispatcher -> tun
    let fut1 = tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            trace!("tun <- dispatcher: {:?}", pkt);
            // populate the correct src_addr, though is it necessary?
            let src_addr = match pkt.src_addr {
                SocksAddr::Ip(ip) => ip,
                SocksAddr::Domain(host, port) => {
                    match resolver.resolve(&host, resolver.fake_ip_enabled()).await {
                        Ok(Some(ip)) => (ip, port).into(),
                        Ok(None) => {
                            warn!("failed to resolve domain: {}", host);
                            continue;
                        }
                        Err(e) => {
                            warn!("failed to resolve domain: {}", e);
                            continue;
                        }
                    }
                }
            };
            if let Err(e) = ls.send_to(
                &pkt.data[..],
                &src_addr,
                &pkt.dst_addr.must_into_socket_addr(),
            ) {
                warn!("failed to send udp packet to netstack: {}", e);
            }
        }
    });

    // tun -> dispatcher
    let fut2 = tokio::spawn(async move {
        while let Ok((data, src_addr, dst_addr)) = lr.recv_from().await {
            if dst_addr.ip().is_multicast() {
                continue;
            }
            let pkt = UdpPacket {
                data,
                src_addr: src_addr.into(),
                dst_addr: dst_addr.into(),
            };

            trace!("tun -> dispatcher: {:?}", pkt);

            match d_tx.send(pkt).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("failed to send udp packet to proxy: {}", e);
                }
            }
        }

        closer.send(0).ok();
    });

    debug!("tun UDP ready");

    let _ = futures::future::join(fut1, fut2).await;
}

pub fn get_runner(
    cfg: TunConfig,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
) -> Result<Option<Runner>, Error> {
    if !cfg.enable {
        trace!("tun is disabled");
        return Ok(None);
    }

    let device_id = cfg.device_id;

    let u = Url::parse(&device_id)
        .map_err(|x| Error::InvalidConfig(format!("tun device {}", x)))?;

    let mut tun_cfg = tun::Configuration::default();

    match u.scheme() {
        "fd" => {
            let fd = u
                .host()
                .expect("tun fd must be provided")
                .to_string()
                .parse()
                .map_err(|x| Error::InvalidConfig(format!("tun fd {}", x)))?;
            tun_cfg.raw_fd(fd);
        }
        "dev" => {
            let dev = u.host().expect("tun dev must be provided").to_string();
            tun_cfg.name(dev);
        }
        _ => {
            return Err(Error::InvalidConfig(format!(
                "invalid device id: {}",
                device_id
            )));
        }
    }

    let gw = cfg.gateway;
    tun_cfg.address(gw.addr()).netmask(gw.netmask()).up();

    let tun = tun::create_as_async(&tun_cfg)
        .map_err(|x| new_io_error(format!("failed to create tun device: {}", x)))?;

    let tun_name = tun.get_ref().name().map_err(map_io_error)?;
    info!("tun started at {}", tun_name);

    #[cfg(target_os = "windows")]
    if cfg.route_all || !cfg.routes.is_empty() {
        let tun_iface = network_interface::NetworkInterface::show()
            .map_err(map_io_error)?
            .into_iter()
            .find(|iface| iface.name == tun_name)
            .map(|x| OutboundInterface {
                name: x.name,
                addr_v4: x.addr.iter().find_map(|addr| match addr {
                    network_interface::Addr::V4(addr) => Some(addr.ip),
                    _ => None,
                }),
                addr_v6: x.addr.iter().find_map(|addr| match addr {
                    network_interface::Addr::V6(addr) => Some(addr.ip),
                    _ => None,
                }),
                index: x.index,
            })
            .expect("tun interface not found");

        if cfg.route_all {
            warn!(
                "route_all is enabled, all traffic will be routed through the tun \
                 interface"
            );
            let default_routes = vec![
                IpNet::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1)
                    .unwrap(),
                IpNet::new(std::net::IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
                    .unwrap(),
            ];
            for r in default_routes {
                add_route(&tun_iface, &r).map_err(map_io_error)?;
            }
        } else {
            for r in cfg.routes {
                add_route(&tun_iface, &r).map_err(map_io_error)?;
            }
        }
    }

    let (stack, mut tcp_listener, udp_socket) =
        netstack::NetStack::with_buffer_size(512, 256).map_err(map_io_error)?;

    Ok(Some(Box::pin(async move {
        let framed = tun.into_framed();

        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let mut futs: Vec<Runner> = vec![];

        // dispatcher -> stack -> tun
        futs.push(Box::pin(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = tun_sink.send(TunPacket::new(pkt)).await {
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
        }));

        // tun -> stack -> dispatcher
        futs.push(Box::pin(async move {
            while let Some(pkt) = tun_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) =
                            stack_sink.send(pkt.into_bytes().into()).await
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
        }));

        let dsp = dispatcher.clone();
        futs.push(Box::pin(async move {
            while let Some((stream, local_addr, remote_addr)) =
                tcp_listener.next().await
            {
                debug!("new tun TCP connection: {} -> {}", local_addr, remote_addr);

                tokio::spawn(handle_inbound_stream(
                    stream,
                    local_addr,
                    remote_addr,
                    dsp.clone(),
                ));
            }

            Err(Error::Operation("tun stopped unexpectedly 2".to_string()))
        }));

        futs.push(Box::pin(async move {
            handle_inbound_datagram(udp_socket, dispatcher, resolver).await;
            Err(Error::Operation("tun stopped unexpectedly 3".to_string()))
        }));

        futures::future::select_all(futs).await.0.map_err(|x| {
            error!("tun error: {}. stopped", x);
            x
        })
    })))
}
