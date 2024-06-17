use super::{datagram::TunDatagram, netstack};
use std::{net::SocketAddr, sync::Arc};

use futures::{SinkExt, StreamExt};
use tracing::{debug, error, info, trace, warn};
use tun::{Device, TunPacket};
use url::Url;

use crate::{
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    common::errors::map_io_error,
    config::internal::config::TunConfig,
    proxy::{datagram::UdpPacket, utils::Interface},
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
        iface: netdev::get_default_interface()
            .map(|x| Interface::Name(x.name))
            .inspect(|x| {
                debug!(
                    "selecting outbound interface: {:?} for tun TCP connection",
                    x
                );
            })
            .ok(),
        ..Default::default()
    };

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

    // for dispatcher - the dispatcher would receive packets from this channel, which is from the stack
    // and send back packets to this channel, which is to the tun
    let udp_stream = TunDatagram::new(l_tx, d_rx, local_addr);

    let sess = Session {
        network: Network::Udp,
        typ: Type::Tun,
        iface: netdev::get_default_interface()
            .map(|x| Interface::Name(x.name))
            .inspect(|x| {
                debug!("selecting outbound interface: {:?} for tun UDP traffic", x);
            })
            .ok(),
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

    let u =
        Url::parse(&device_id).map_err(|x| Error::InvalidConfig(format!("tun device {}", x)))?;

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

    tun_cfg.up();

    let tun = tun::create_as_async(&tun_cfg).map_err(map_io_error)?;

    let tun_name = tun.get_ref().name().map_err(map_io_error)?;
    info!("tun started at {}", tun_name);

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
                        if let Err(e) = stack_sink.send(pkt.into_bytes().into()).await {
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
            while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
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
