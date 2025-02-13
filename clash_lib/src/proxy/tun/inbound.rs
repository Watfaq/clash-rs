use super::{datagram::TunDatagram, netstack};
use std::{net::SocketAddr, sync::Arc};

use futures::{SinkExt, StreamExt};

use tracing::{debug, error, info, trace, warn};
use tun::{Device, TunPacket};
use url::Url;

use crate::{
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    common::errors::{map_io_error, new_io_error},
    config::internal::config::TunConfig,
    proxy::{
        datagram::UdpPacket, tun::routes::maybe_add_routes,
        utils::get_outbound_interface,
    },
    session::{Network, Session, Type},
    Error, Runner,
};

use crate::{defer, proxy::tun::routes};

const DEFAULT_SO_MARK: u32 = 3389;
const DEFAULT_ROUTE_TABLE: u32 = 2468;

async fn handle_inbound_stream(
    stream: netstack::TcpStream,
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
            .map(|x| crate::proxy::utils::Interface::Name(x.name))
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
    dispatcher.dispatch_stream(sess, Box::new(super::stream::StreamWrapper::new(stream))).await;
}

async fn handle_inbound_datagram(
    socket: Box<netstack::UdpSocket>,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: u32,
    dns_hijack: bool,
) {
    // tun i/o
    let (ls, mut lr) = socket.split();
    let ls = Arc::new(ls);
    let ls_dns = ls.clone(); // for dns hijack
    let resolver_dns = resolver.clone(); // for dns hijack

    // dispatcher <-> tun communications
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
            .map(|x| crate::proxy::utils::Interface::Name(x.name))
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
            if let Err(e) = ls.send_to(
                &pkt.data[..],
                &pkt.src_addr.must_into_socket_addr(),
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

            if dns_hijack && pkt.dst_addr.port() == 53 {
                trace!("got dns packet: {:?}, returning from Clash DNS server", pkt);

                match hickory_proto::op::Message::from_vec(&pkt.data) {
                    Ok(msg) => {
                        trace!("hijack dns request: {:?}", msg);
                        let mut resp = match resolver_dns.exchange(&msg).await {
                            Ok(resp) => resp,
                            Err(e) => {
                                warn!("failed to exchange dns message: {}", e);
                                continue;
                            }
                        };
                        // hickory mutates id sometimes, https://github.com/hickory-dns/hickory-dns/pull/2590
                        resp.set_id(msg.id());

                        if let Some(edns) = msg.extensions() {
                            if edns
                                .option(
                                    hickory_proto::rr::rdata::opt::EdnsCode::Padding,
                                )
                                .is_none()
                            {
                                if let Some(edns) = resp.extensions_mut() {
                                    edns.options_mut().remove(
                                        hickory_proto::rr::rdata::opt::EdnsCode::Padding,
                                    );
                                }
                            }
                        }
                        trace!("hijack dns response: {:?}", resp);

                        match resp.to_vec() {
                            Ok(data) => {
                                if let Err(e) = ls_dns.send_to(
                                    &data,
                                    &pkt.dst_addr.must_into_socket_addr(),
                                    &pkt.src_addr.must_into_socket_addr(),
                                ) {
                                    warn!(
                                        "failed to send udp packet to netstack: {}",
                                        e
                                    );
                                }
                                continue;
                            }
                            Err(e) => {
                                warn!("failed to serialize dns response: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "failed to parse dns packet: {}, putting it back to \
                             stack",
                            e
                        );
                    }
                };
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

    let device_id = &cfg.device_id;

    let u = Url::parse(device_id)
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
    tun_cfg
        .address(gw.addr())
        .netmask(gw.netmask())
        .mtu(cfg.mtu.unwrap_or(if cfg!(windows) { 65535 } else { 1500 }))
        .up();

    let tun = tun::create_as_async(&tun_cfg)
        .map_err(|x| new_io_error(format!("failed to create tun device: {}", x)))?;

    let tun_name = tun.get_ref().name().map_err(map_io_error)?;
    info!("tun started at {}", tun_name);

    let mut cfg = cfg;
    cfg.route_table = cfg.route_table.or(Some(DEFAULT_ROUTE_TABLE));
    cfg.so_mark = cfg.so_mark.or(Some(DEFAULT_SO_MARK));

    maybe_add_routes(&cfg, &tun_name)?;

    let (stack, mut tcp_listener, udp_socket) =
        netstack::NetStack::with_buffer_size(512, 256).map_err(map_io_error)?;

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

        let so_mark = cfg.so_mark.unwrap();

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
