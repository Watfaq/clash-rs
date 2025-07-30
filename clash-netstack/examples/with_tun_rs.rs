//! To test this example, you can run the following commands:
//! ```bash
//! cargo run --example with_tun_rs
//! sudo route add -host 1.1.1.1 -interface utun1989
//! ```
//! TCP with curl:
//! ```bash
//! curl -v 1.1.1.1
//! ```
//! UDP with dig:
//! ```bash
//! dig google.com @1.1.1.1
//! ```
//! This example demonstrates how to use the `watfaq_netstack` library with a
//! TUN device created using `tun_rs`. It sets up a basic network stack that can
//! handle TCP and UDP traffic through the TUN interface.
use std::{ffi::CString, net::SocketAddr, sync::Arc};

use futures::{SinkExt, StreamExt};
use log::{debug, error, warn};
use tokio::net::{TcpSocket, TcpStream};
use tun_rs::DeviceBuilder;

type Runner = futures::future::BoxFuture<'static, std::io::Result<()>>;

static OUTBOUND_INTERFACE: &str = "en0"; // Change this to your actual outbound interface name

fn get_interface_index(iface: &str) -> u32 {
    unsafe {
        let c_string = CString::new(iface).expect("Failed to create CString");
        libc::if_nametoindex(c_string.as_ptr())
    }
}

async fn new_tcp_stream<'a>(
    addr: SocketAddr,
    iface: &str,
) -> std::io::Result<TcpStream> {
    let socket =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let iface_index = get_interface_index(iface);
    assert_ne!(iface_index, 0, "interface index must not be zero");
    socket.bind_device_by_index_v4(iface_index.try_into().ok())?;
    socket.set_keepalive(true)?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    let stream = TcpSocket::from_std_stream(socket.into())
        .connect(addr)
        .await?;

    Ok(stream)
}

async fn new_udp_packet(iface: &str) -> std::io::Result<tokio::net::UdpSocket> {
    let socket =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let iface_index = get_interface_index(iface);
    assert_ne!(iface_index, 0, "interface index must not be zero");
    socket.bind_device_by_index_v4(iface_index.try_into().ok())?;
    socket.set_nonblocking(true)?;

    tokio::net::UdpSocket::from_std(socket.into())
}

async fn handle_inbound_stream(mut stream: watfaq_netstack::TcpStream) {
    match new_tcp_stream(stream.remote_addr(), &OUTBOUND_INTERFACE).await {
        Ok(mut remote_stream) => {
            // pipe between two tcp stream
            match tokio::io::copy_bidirectional(&mut stream, &mut remote_stream)
                .await
            {
                Ok(_) => {}
                Err(e) => warn!("error while copying data between streams: {}", e),
            }
        }
        Err(e) => warn!(
            "failed to connect to remote {}: {}",
            stream.remote_addr(),
            e
        ),
    }
}

async fn handle_inbound_datagram(socket: watfaq_netstack::UdpSocket) {
    let (mut r, w) = socket.split();
    while let Some(packet) = r.recv().await {
        debug!("received UDP packet from tun inbound {packet:?}");

        let u = Arc::new(new_udp_packet(OUTBOUND_INTERFACE).await.unwrap());
        let uc = u.clone();
        let mut w = w.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while let Ok((n, peer)) = uc.recv_from(&mut buf).await {
                debug!(
                    "received UDP packet from remote reply {n} bytes from {peer}"
                );
                w.send(watfaq_netstack::UdpPacket {
                    data: watfaq_netstack::Packet::new(buf[..n].to_vec()),
                    local_addr: peer,
                    remote_addr: packet.local_addr,
                })
                .await
                .expect("Failed to send UDP packet");
            }
        });

        if let Err(e) = u.send_to(packet.data(), packet.remote_addr).await {
            error!("failed to send UDP packet: {}", e);
        } else {
            debug!("forwarding UDP packet to remote {}", packet.remote_addr);
        }
    }
}

fn add_test_routes(tun_name: &str) {
    // This function is used to add test routes for the TUN device.
    // The actual implementation will depend on your system and requirements.
    // For example, you might use `route` command on Unix-like systems.
    // Here we assume the route is already added in the example description.
    let _ = std::process::Command::new("route")
        .arg("add")
        .arg("-host")
        .arg("1.1.1.1")
        .arg("-interface")
        .arg(tun_name)
        .output();
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("trace"),
    )
    .format_source_path(true)
    .format_timestamp_micros()
    .init();
    let gateway_v4: ipnet::Ipv4Net = "198.19.0.1/24".parse().unwrap();
    let gateway_v6: ipnet::Ipv6Net = "2001:db8::1/64".parse().unwrap();
    let tun_name = "utun1989";
    let tun_builder = DeviceBuilder::new()
        .name(tun_name)
        .mtu(
            1500, // Default MTU for TUN devices
        )
        .associate_route(false)
        .ipv4(gateway_v4.addr(), gateway_v4.netmask(), None)
        .ipv6(gateway_v6.addr(), gateway_v6.netmask());

    let dev = tun_builder.build_async().expect("must create tun device");

    add_test_routes(tun_name);

    let (stack, mut tcp_listener, udp_socket) = watfaq_netstack::NetStack::new();

    let framed = tun_rs::async_framed::DeviceFramed::new(
        dev,
        tun_rs::async_framed::BytesCodec::new(),
    );

    let (mut tun_sink, mut tun_stream) = framed.split::<bytes::Bytes>();
    let (mut stack_sink, mut stack_stream) = stack.split();

    let mut futs: Vec<Runner> = vec![];

    // dispatcher -> stack -> tun
    futs.push(Box::pin(async move {
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

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tun stopped unexpectedly 0",
        ))
    }));

    // tun -> stack -> dispatcher
    futs.push(Box::pin(async move {
        while let Some(pkt) = tun_stream.next().await {
            match pkt {
                Ok(pkt) => {
                    if let Err(e) =
                        stack_sink.send(watfaq_netstack::Packet::new(pkt)).await
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

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tun stopped unexpectedly 1",
        ))
    }));

    futs.push(Box::pin(async move {
        while let Some(stream) = tcp_listener.next().await {
            debug!(
                "new tun TCP connection: {} -> {}",
                stream.local_addr(),
                stream.remote_addr()
            );

            tokio::spawn(handle_inbound_stream(stream));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tun TCP listener stopped unexpectedly",
        ))
    }));

    futs.push(Box::pin(async move {
        handle_inbound_datagram(udp_socket).await;
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tun UDP listener stopped unexpectedly",
        ))
    }));

    futures::future::select_all(futs)
        .await
        .0
        .map_err(|x| {
            error!("tun error: {}. stopped", x);
            x
        })
        .expect("tun runner should not return error");
}
