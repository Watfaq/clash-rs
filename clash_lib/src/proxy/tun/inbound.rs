use super::datagram::TunDatagram;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use futures::{SinkExt, StreamExt};

use hickory_proto::rr::RecordType;
use netstack_smoltcp::StackBuilder;
use tracing::{debug, error, info, trace, warn};
use tun::AbstractDevice;
use url::Url;

use crate::{
    Error, Runner,
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, exchange_with_resolver},
        net::get_outbound_interface,
    },
    common::errors::{map_io_error, new_io_error},
    config::internal::config::TunConfig,
    proxy::{datagram::UdpPacket, tun::routes::maybe_add_routes},
    session::{Network, Session, Type},
};

use crate::{defer, proxy::tun::routes};

async fn handle_inbound_stream(
    stream: netstack_smoltcp::TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    so_mark: u32,
) {
    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source: local_addr,
        destination: remote_addr.into(),
        iface: get_outbound_interface()
            .map(|x| x.name.as_str().into())
            .inspect(|x| {
                debug!(
                    "selecting outbound interface: {:?} for tun TCP connection",
                    x
                );
            }),
        so_mark: Some(so_mark),
        ..Default::default()
    };

    debug!("new tun TCP session assigned: {}", sess);
    dispatcher.dispatch_stream(sess, Box::new(stream)).await;
}

async fn handle_inbound_datagram(
    socket: netstack_smoltcp::UdpSocket,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: u32,
    dns_hijack: bool,
) {
    // tun i/o
    // lr: app packets went into tun will be accessed from lr
    // ls: packet writen into ls will go back to app from tun
    let (mut lr, mut ls) = socket.split();
    // ideally we clone the WriteHalf ls, but it's not Clone and it's a Sink so the
    // send method is mut
    let (dup_ls, mut dup_lr) = tokio::sync::mpsc::channel(32);
    tokio::spawn(async move {
        while let Some((data, local, remote)) = dup_lr.recv().await {
            if let Err(e) = ls.send((data, local, remote)).await {
                warn!("failed to send udp packet to netstack: {}", e);
            }
        }
    });
    let ls = dup_ls.clone();
    let ls_dns = dup_ls.clone(); // for dns hijack
    let resolver_dns = resolver.clone(); // for dns hijack

    // dispatcher <-> tun communications
    // l_tx: dispatcher write packet responsed from remote proxy
    // l_rx: in fut1 items are forwared to ls
    let (l_tx, mut l_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

    // forward packets from tun to dispatcher
    let (d_tx, d_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

    // for dispatcher - the dispatcher would receive packets from this channel,
    // which is from the stack and send back packets to this channel, which
    // is to the tun
    let udp_stream = TunDatagram::new(l_tx, d_rx);

    let sess = Session {
        network: Network::Udp,
        typ: Type::Tun,
        iface: get_outbound_interface()
            .map(|x| x.name.as_str().into())
            .inspect(|x| {
                debug!("selecting outbound interface: {:?} for tun UDP traffic", x);
            }),
        so_mark: Some(so_mark),
        ..Default::default()
    };

    let closer = dispatcher
        .dispatch_datagram(sess, Box::new(udp_stream))
        .await;

    // dispatcher -> tun
    let fut1 = tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            trace!("tun <- dispatcher: {:?}", pkt);
            if let Err(e) = ls
                .send((
                    pkt.data,
                    pkt.src_addr.must_into_socket_addr(),
                    pkt.dst_addr.must_into_socket_addr(),
                ))
                .await
            {
                warn!("failed to send udp packet to netstack: {}", e);
            }
        }
    });

    // tun -> dispatcher
    let fut2 = tokio::spawn(async move {
        'read_packet: while let Some((data, src_addr, dst_addr)) = lr.next().await {
            if dst_addr.ip().is_multicast() {
                continue;
            }
            let pkt = UdpPacket {
                data,
                src_addr: src_addr.into(),
                dst_addr: dst_addr.into(),
            };

            trace!("tun -> dispatcher: {:?}", pkt);

            if dns_hijack && pkt.dst_addr.port() == 53 {
                trace!("got dns packet: {:?}, returning from Clash DNS server", pkt);

                match hickory_proto::op::Message::from_vec(&pkt.data) {
                    Ok(msg) => {
                        let send_response =
                            async |msg: hickory_proto::op::Message,
                                   pkt: &UdpPacket| {
                                match msg.to_vec() {
                                    Ok(data) => {
                                        if let Err(e) = ls_dns
                                            .send((
                                                data,
                                                pkt.dst_addr
                                                    .clone()
                                                    .must_into_socket_addr(),
                                                pkt.src_addr
                                                    .clone()
                                                    .must_into_socket_addr(),
                                            ))
                                            .await
                                        {
                                            warn!(
                                                "failed to send udp packet to \
                                                 netstack: {}",
                                                e
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            "failed to serialize dns response: {}",
                                            e
                                        );
                                    }
                                }
                            };

                        trace!("hijack dns request: {:?}", msg);
                        if msg.query().map(|q| q.query_type())
                            == Some(RecordType::AAAA)
                        {
                            trace!("dns hijack does not support AAAA query");
                            let resp = hickory_proto::op::Message::error_msg(
                                msg.id(),
                                msg.op_code(),
                                hickory_proto::op::ResponseCode::Refused,
                            );
                            send_response(resp, &pkt).await;
                            continue 'read_packet;
                        }

                        let mut resp =
                            match exchange_with_resolver(&resolver_dns, &msg, true)
                                .await
                            {
                                Ok(resp) => resp,
                                Err(e) => {
                                    warn!("failed to exchange dns message: {}", e);
                                    continue 'read_packet;
                                }
                            };

                        // TODO: figure out where the message id got lost
                        resp.set_id(msg.id());
                        trace!("hijack dns response: {:?}", resp);

                        send_response(resp, &pkt).await;
                    }
                    Err(e) => {
                        warn!(
                            "failed to parse dns packet: {}, putting it back to \
                             stack",
                            e
                        );
                    }
                };

                // don't forward dns packet to dispatcher
                continue 'read_packet;
            }

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

    let mut tun_cfg = tun::Configuration::default();

    match Url::parse(&cfg.device_id) {
        Ok(u) => {
            warn!("todo: URL format configuration will no longer be supported.");
            match u.scheme() {
                "fd" => {
                    let fd = u
                        .host()
                        .expect("tun fd must be provided")
                        .to_string()
                        .parse()
                        .map_err(|x| {
                            Error::InvalidConfig(format!("tun fd {}", x))
                        })?;
                    tun_cfg.raw_fd(fd);
                }
                "dev" => {
                    let dev =
                        u.host().expect("tun dev must be provided").to_string();
                    if cfg!(target_os = "macos") {
                        if !dev.starts_with("utun") {
                            return Err(Error::InvalidConfig(format!(
                                "invalid device id: {}. tun name must be utunX",
                                cfg.device_id
                            )));
                        }
                    }
                    tun_cfg.tun_name(dev);
                }
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "invalid device id: {}",
                        cfg.device_id
                    )));
                }
            }
        }
        Err(_) => {
            if cfg!(target_os = "macos") {
                if !&cfg.device_id.starts_with("utun") {
                    return Err(Error::InvalidConfig(format!(
                        "invalid device id: {}. tun name must be utunX",
                        cfg.device_id
                    )));
                }
            }
            tun_cfg.tun_name(&cfg.device_id);
        }
    }

    let gw = cfg.gateway;
    tun_cfg
        .address(gw.addr())
        .netmask(gw.netmask())
        .mtu(
            cfg.mtu
                .unwrap_or(if cfg!(windows) { 65535u16 } else { 1500u16 }),
        )
        .up();

    let tun = tun::create_as_async(&tun_cfg)
        .map_err(|x| new_io_error(format!("failed to create tun device: {}", x)))?;

    let tun_name = tun.tun_name().map_err(map_io_error)?;
    info!("tun started at {}", tun_name);

    maybe_add_routes(&cfg, &tun_name)?;

    let mut builder = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true);
    if let Some(device_broadcast) = get_device_broadcast(&tun) {
        builder = builder
            // .add_ip_filter(Box::new(move |src, dst| *src != device_broadcast && *dst != device_broadcast));
            .add_ip_filter_fn(move |src, dst| *src != device_broadcast && *dst != device_broadcast);
    }
    let (stack, runner, udp_socket, tcp_listener) = builder.build().unwrap();
    let udp_socket = udp_socket.unwrap(); // udp enabled
    let mut tcp_listener = tcp_listener.unwrap(); // tcp enabled or icmp enabled
    if let Some(runner) = runner {
        tokio::spawn(runner);
    }

    Ok(Some(Box::pin(async move {
        defer! {
            warn!("cleaning up routes");

            match routes::maybe_routes_clean_up(&cfg) {
                Ok(_) => {}
                Err(e) => {
                    error!("failed to clean up routes: {}", e);
                }
            }
        }

        let so_mark = cfg.so_mark;

        let framed = tun.into_framed();

        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let mut futs: Vec<Runner> = vec![];

        // dispatcher -> stack -> tun
        futs.push(Box::pin(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = tun_sink.send(pkt).await {
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
                        if let Err(e) = stack_sink.send(pkt).await {
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
                    so_mark,
                ));
            }

            Err(Error::Operation("tun stopped unexpectedly 2".to_string()))
        }));

        futs.push(Box::pin(async move {
            handle_inbound_datagram(
                udp_socket,
                dispatcher,
                resolver,
                so_mark,
                cfg.dns_hijack,
            )
            .await;
            Err(Error::Operation("tun stopped unexpectedly 3".to_string()))
        }));

        futures::future::select_all(futs).await.0.map_err(|x| {
            error!("tun error: {}. stopped", x);
            x
        })
    })))
}

fn get_device_broadcast(device: &tun::AsyncDevice) -> Option<std::net::Ipv4Addr> {
    let mtu = device.mtu().unwrap();

    let address = match device.address() {
        Ok(a) => match a {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return None,
        },
        Err(_) => return None,
    };

    let netmask = match device.netmask() {
        Ok(n) => match n {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return None,
        },
        Err(_) => return None,
    };

    match smoltcp::wire::Ipv4Cidr::from_netmask(address, netmask) {
        Ok(address_net) => match address_net.broadcast() {
            Some(broadcast) => {
                info!(
                    "tun device network: {} (address: {}, netmask: {}, broadcast: \
                     {}, mtu: {})",
                    address_net, address, netmask, broadcast, mtu,
                );

                Some(broadcast)
            }
            None => {
                error!("invalid tun address {}, netmask {}", address, netmask);
                None
            }
        },
        Err(err) => {
            error!(
                "invalid tun address {}, netmask {}, error: {}",
                address, netmask, err
            );
            None
        }
    }
}
