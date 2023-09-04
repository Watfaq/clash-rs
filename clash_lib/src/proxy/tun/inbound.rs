use super::{datagram::TunDatagram, netstack};
use std::{net::SocketAddr, sync::Arc};

use futures::{SinkExt, StreamExt};
use tracing::{error, info, warn};
use tun::TunPacket;
use url::Url;

use crate::{
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::internal::config::TunConfig,
    proxy::datagram::UdpPacket,
    session::{Network, Session, SocksAddr},
    Runner,
};

async fn handl_inbound_stream(
    stream: netstack::TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
) {
    let mut sess = Session {
        network: Network::Tcp,
        source: local_addr,
        destination: remote_addr.into(),
        ..Default::default()
    };

    if resolver.fake_ip_enabled() && resolver.is_fake_ip(remote_addr.ip()).await {
        if let Some(host) = resolver.reverse_lookup(remote_addr.ip()).await {
            sess.destination = (host, remote_addr.port()).try_into().unwrap();
        } else {
            error!("failed to resolve fake ip: {}", remote_addr.ip());
            return;
        }
    }

    dispatcher.dispatch_stream(sess, stream).await;
}

async fn handle_inbound_datagram(
    socket: Box<netstack::UdpSocket>,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
) {
    // netstack communications
    let (ls, mut lr) = socket.split();
    let ls = Arc::new(ls);

    let (l_tx, mut l_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

    let (d_tx, mut d_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

    // for dispatcher - the dispatcher would receive packets from this channel, which is from the stack
    // and send back packets to this channel, which is to the tun
    let udp_stream = TunDatagram::new(l_tx, d_rx);

    tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            let src_addr = match pkt.src_addr {
                SocksAddr::Ip(ip) => ip,
                SocksAddr::Domain(host, port) => {
                    if let Some(ip) = resolver.lookup_fake_ip(&host).await {
                        (ip, port).into()
                    } else {
                        warn!("failed to resolve fake ip: {}", host);
                        continue;
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

    tokio::spawn(async move {
        // TODO: handle DNS
        while let Ok((data, src_addr, dst_addr)) = lr.recv_from().await {
            let pkt = UdpPacket {
                data,
                src_addr: src_addr.into(),
                dst_addr: dst_addr.into(),
            };

            match d_tx.send(pkt).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("failed to send udp packet to proxy: {}", e);
                }
            }
        }
    });

    let sess = Session {
        network: Network::Udp,
        ..Default::default()
    };

    dispatcher.dispatch_datagram(sess, Box::new(udp_stream));
}

pub fn get_runner(
    cfg: TunConfig,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
) -> anyhow::Result<Runner> {
    if !cfg.enable {
        return Ok(Box::pin(async {}));
    }

    let device_id = cfg.device_id;

    let u = Url::parse(&device_id)?;

    let mut tun_cfg = tun::Configuration::default();

    match u.scheme() {
        "fd" => {
            let fd = u.path().parse()?;
            tun_cfg.raw_fd(fd);
        }
        "dev" => {
            let dev = u.path();
            tun_cfg.name(dev);
        }
        _ => {
            return Err(anyhow!("invalid device id: {}", device_id));
        }
    }

    tun_cfg.up();

    let tun = tun::create_as_async(&tun_cfg)?;

    let (stack, mut tcp_listener, udp_socket) = netstack::NetStack::with_buffer_size(512, 256)?;

    Ok(Box::pin(async move {
        let framed = tun.into_framed();

        let (mut tun_sink, mut tun_stream) = framed.split();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let mut futs: Vec<Runner> = vec![];

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
        }));

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
        }));

        let dsp = dispatcher.clone();
        let rsv = resolver.clone();
        futs.push(Box::pin(async move {
            while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
                tokio::spawn(handl_inbound_stream(
                    stream,
                    local_addr,
                    remote_addr,
                    dsp.clone(),
                    rsv.clone(),
                ));
            }
        }));

        futs.push(Box::pin(async move {
            handle_inbound_datagram(udp_socket, dispatcher, resolver).await;
        }));

        info!("tun started");
        futures::future::select_all(futs).await;
    }))
}
