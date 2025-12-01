#[cfg(any(target_os = "macos", target_os = "linux"))]
mod macos {
    //! To test this example, you can run the following commands:
    //! ```bash
    //! cargo run --example with_tun_rs
    //! ```
    //! TCP with curl:
    //! ```bash
    //! curl -v 1.1.1.1
    //! curl -6 -v '[2606:4700:4700::1111]'
    //! ```
    //! UDP with dig:
    //! ```bash
    //! dig google.com @1.1.1.1
    //! dig -6 google.com @2606:4700:4700::1111
    //! ```
    //! This example demonstrates how to use the `watfaq_netstack` library with
    //! a TUN device created using `tun_rs`. It sets up a basic network
    //! stack that can handle TCP and UDP traffic through the TUN interface.
    use std::{ffi::CString, net::SocketAddr};

    use futures::{SinkExt, StreamExt};
    use log::{error, trace, warn};
    use tokio::net::{TcpSocket, TcpStream};
    use tun_rs::DeviceBuilder;

    type Runner = futures::future::BoxFuture<'static, std::io::Result<()>>;

    static OUTBOUND_INTERFACE: &str = "eth0"; // Change this to your actual outbound interface name

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
        let socket = socket2::Socket::new(
            if addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::STREAM,
            None,
        )?;
        let iface_index = get_interface_index(iface);
        assert_ne!(iface_index, 0, "interface index must not be zero");
        if addr.is_ipv4() {
            socket.bind_device_by_index_v4(iface_index.try_into().ok())?;
        } else {
            socket.bind_device_by_index_v6(iface_index.try_into().ok())?;
        }
        socket.set_keepalive(true)?;
        socket.set_tcp_nodelay(true)?;
        socket.set_nonblocking(true)?;

        let stream = TcpSocket::from_std_stream(socket.into())
            .connect(addr)
            .await?;

        Ok(stream)
    }

    #[allow(unused)]
    async fn new_udp_packet(iface: &str) -> std::io::Result<tokio::net::UdpSocket> {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
        socket.set_only_v6(false)?;
        let iface_index = get_interface_index(iface);
        assert_ne!(iface_index, 0, "interface index must not be zero");
        socket.bind_device_by_index_v6(iface_index.try_into().ok())?;
        socket.set_nonblocking(true)?;

        tokio::net::UdpSocket::from_std(socket.into())
    }

    async fn handle_inbound_stream(mut stream: netstack_smoltcp::TcpStream) {
        let start = std::time::Instant::now();
        let mut remote_stream =
            new_tcp_stream(*stream.remote_addr(), &OUTBOUND_INTERFACE)
                .await
                .expect("Failed to connect to remote stream");

        trace!(
            "Connected to remote {} in {} ms",
            stream.remote_addr(),
            start.elapsed().as_millis()
        );
        match tokio::io::copy_bidirectional(&mut stream, &mut remote_stream).await {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to copy bidirectional stream: {}", e);
            }
        }
    }

    fn add_test_routes(tun_name: &str) {
        #[cfg(target_os = "macos")]
        {
            // This function is used to add test routes for the TUN device.
            // The actual implementation will depend on your system and requirements.
            // For example, you might use `route` command on Unix-like systems.
            // Here we assume the route is already added in the example description.
            let output = std::process::Command::new("route")
                .arg("add")
                .arg("-host")
                .arg("10.0.0.11")
                .arg("-interface")
                .arg(tun_name)
                .output()
                .expect("must add route for");
            if !output.status.success() {
                error!(
                    "Failed to add route for {}: {}",
                    tun_name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            warn!(
                "output of route add: {}",
                String::from_utf8_lossy(&output.stdout)
            );

            let output = std::process::Command::new("route")
                .arg("add")
                .arg("-inet6")
                .arg("-host")
                .arg("2606:4700:4700::1111")
                .arg("-interface")
                .arg(tun_name)
                .output()
                .expect("must add route for");
            if !output.status.success() {
                error!(
                    "Failed to add IPv6 route for {}: {}",
                    tun_name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            warn!(
                "output of IPv6 route add: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }

        #[cfg(target_os = "linux")]
        {
            // For Linux, you might use `ip` command to add routes.
            let output = std::process::Command::new("ip")
                .arg("route")
                .arg("add")
                .arg("10.0.0.11/32")
                .arg("dev")
                .arg(tun_name)
                .output()
                .expect("must add route for");
            if !output.status.success() {
                error!(
                    "Failed to add route for {}: {}",
                    tun_name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            warn!(
                "output of route add: {}",
                String::from_utf8_lossy(&output.stdout)
            );

            let output = std::process::Command::new("ip")
                .arg("route")
                .arg("add")
                .arg("2606:4700:4700::1111/128")
                .arg("dev")
                .arg(tun_name)
                .output()
                .expect("must add route for");
            if !output.status.success() {
                error!(
                    "Failed to add IPv6 route for {}: {}",
                    tun_name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            warn!(
                "output of IPv6 route add: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }

    pub(super) async fn main() {
        let gateway_v4: ipnet::Ipv4Net = "198.19.0.1/24".parse().unwrap();
        let gateway_v6: ipnet::Ipv6Net = "fc00:fac::1/64".parse().unwrap();
        let tun_name = "utun1989";
        let tun_builder = DeviceBuilder::new()
            .name(tun_name)
            .mtu(
                1500, // Default MTU for TUN devices
            )
            .ipv4(gateway_v4.addr(), gateway_v4.netmask(), None)
            .ipv6(gateway_v6.addr(), gateway_v6.netmask());

        #[cfg(target_os = "macos")]
        let tun_builder = tun_builder.associate_route(false);

        let dev = tun_builder.build_async().expect("must create tun device");

        add_test_routes(tun_name);

        let (stack, runner, _udp_socket, tcp_listener) =
            netstack_smoltcp::StackBuilder::default()
                .stack_buffer_size(512)
                .tcp_buffer_size(4096)
                .enable_udp(true)
                .enable_tcp(true)
                .enable_icmp(true)
                .build()
                .unwrap();
        let mut _udp_socket = _udp_socket.unwrap(); // udp enabled
        let mut tcp_listener = tcp_listener.unwrap(); // tcp/icmp enabled
        if let Some(runner) = runner {
            tokio::spawn(runner);
        }
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
                        if let Err(e) = tun_sink.send(pkt.into()).await {
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
                        if let Err(e) = stack_sink.send(pkt.into()).await {
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
            while let Some((stream, src, dst)) = tcp_listener.next().await {
                warn!("New TCP stream: {} <-> {}", src, dst);
                tokio::spawn(handle_inbound_stream(stream));
            }

            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "tun TCP listener stopped unexpectedly",
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
}

#[tokio::main]
async fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::WARN)
            .finish(),
    )
    .unwrap();

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    macos::main().await;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        panic!(
            "This example is only for macOS and Linux with tun_rs. Please run it \
             on macOS or Linux."
        );
    }
}
