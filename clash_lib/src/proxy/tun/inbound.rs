use super::datagram::TunDatagram;
use std::{net::SocketAddr, sync::Arc};

use futures::{SinkExt, StreamExt};
use tracing::{info, trace, warn};
use url::Url;

use crate::{
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::internal::config::TunConfig,
    proxy::datagram::UdpPacket,
    session::{Network, Session, SocksAddr, Type},
    Error, Runner,
};

async fn handle_inbound_stream(
    stream: libtun::TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
) {
    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source: local_addr,
        destination: remote_addr.into(),
        ..Default::default()
    };

    dispatcher.dispatch_stream(sess, stream).await;
}

async fn handle_inbound_datagram(
    socket: libtun::UdpSocket,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
) {
    let (mut read_half, mut write_half) = socket.split();

    let (d2tun_tx, mut d2tun_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
    let (tun2d_tx, tun2d_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
    
    let udp_stream = TunDatagram::new(d2tun_tx, tun2d_rx);

    let sess = Session {
        network: Network::Udp,
        typ: Type::Tun,
        ..Default::default()
    };
    // TODO refactor `closer`
    let closer = dispatcher.dispatch_datagram(sess, Box::new(udp_stream));

    loop {
        // !!! Cancellation safety **must** be guaranteed.
        tokio::select! {
            // dispatcher -> tun
            Some(pkt) = d2tun_rx.recv() => {
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
                if let Err(e) = write_half.send((
                    pkt.data,
                    src_addr,
                    pkt.dst_addr.must_into_socket_addr(),
                )).await {
                    warn!("failed to send udp packet to netstack: {}", e);
                }
            }
            Some((data, src_addr, dst_addr)) = read_half.next() => {
                let pkt = UdpPacket {
                    data,
                    src_addr: src_addr.into(),
                    dst_addr: dst_addr.into(),
                };
    
                trace!("tun -> dispatcher: {:?}", pkt);
    
                match tun2d_tx.send(pkt).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("failed to send udp packet to proxy: {}", e);
                    }
                }
            }
        }
    }
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

    let device_id: libtun::DeviceID;
    match u.scheme() {
        "fd" => {
            let fd = u
                .host()
                .expect("tun fd must be provided")
                .to_string()
                .parse()
                .map_err(|x| Error::InvalidConfig(format!("tun fd {}", x)))?;
            device_id = libtun::DeviceID::Fd(fd);
        }
        "dev" => {
            let dev = u.host().expect("tun dev must be provided").to_string();
            device_id = libtun::DeviceID::Dev(dev);
        }
        _ => {
            // TODO Warning
            device_id = libtun::DeviceID::default();
        }
    }
    let mut tun_system = libtun::TunSystem::new(device_id, true);
    tun_system.create_device();

    info!("tun started at {}", tun_system.device_name());
    let (mut tcp_listener, udp_socket) = tun_system.create_netstack();

    let dispatcher_clone = dispatcher.clone();
    let tcp_task = tokio::spawn(async move{
        
        while let Some((
            stream, 
            local_addr, 
            remote_addr
        )) = tcp_listener.next().await {
            tokio::spawn(handle_inbound_stream(
                stream,
                local_addr,
                remote_addr,
                dispatcher_clone.clone(),
            ));
        }
    });

    let dispatcher_clone = dispatcher.clone();
    let udp_task = tokio::spawn(async move{
        handle_inbound_datagram(udp_socket, dispatcher_clone, resolver).await;
    });

    Ok(Some(Box::pin(async move { 
        _ = futures::future::join(tcp_task, udp_task).await;
        Ok(())
    })))
}
