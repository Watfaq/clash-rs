use crate::{
    Packet, device::NetstackDevice, packet::IpPacket, spin_lock::Protected,
    tcp_stream::TcpStream,
};
use log::{error, trace, warn};
use smoltcp::{
    iface::Interface,
    socket::tcp,
    storage::RingBuffer,
    wire::{IpProtocol, TcpPacket},
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;

// NOTE: Default buffer could contain 20 AEAD packets
const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = 0x3FFF * 20;
const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = 0x3FFF * 20;

#[derive(Clone)]
pub(crate) struct TcpStreamHandle {
    pub(crate) recv_buffer: Arc<Protected<RingBuffer<'static, u8>>>,
    pub(crate) send_buffer: Arc<Protected<RingBuffer<'static, u8>>>,
}
impl Drop for TcpStreamHandle {
    fn drop(&mut self) {
        trace!("TcpStreamHandle dropped");
    }
}

enum IfaceEvent<'a> {
    Icmp,                                          // ICMP packet received
    TcpStream((tcp::Socket<'a>, TcpStreamHandle)), // TCP stream event
}

pub struct TcpListener {
    socket_stream: mpsc::UnboundedReceiver<TcpStream>,
}

impl TcpListener {
    pub fn new(
        inbound: mpsc::UnboundedReceiver<Packet>,
        outbound: mpsc::UnboundedSender<Packet>,
    ) -> Self {
        let mut config =
            smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut device = NetstackDevice::new(outbound);
        let mut iface = smoltcp::iface::Interface::new(
            config,
            &mut device,
            smoltcp::time::Instant::now(),
        );
        iface.set_any_ip(true);
        iface.update_ip_addrs(|ip_addrs| {
            let _ = ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::Ipv4Address::new(10, 0, 0, 1).into(),
                24,
            ));
            let _ = ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::Ipv6Address::new(0x0, 0xfac, 0, 0, 0, 0, 0, 1).into(),
                64,
            ));
        });

        let (socket_stream_emitter, socket_stream) =
            mpsc::unbounded_channel::<TcpStream>();

        let (iface_notifier, iface_notifier_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            tokio::select! {
                _ = Self::poll_packets(inbound, device.create_injector(), iface_notifier, socket_stream_emitter) => {},
                _ = Self::poll_sockets(&mut iface, &mut device, iface_notifier_rx) => {},
            }
        });

        TcpListener { socket_stream }
    }

    async fn poll_packets(
        mut inbound: mpsc::UnboundedReceiver<Packet>,
        device_injector: mpsc::UnboundedSender<Packet>,
        iface_notifier: mpsc::UnboundedSender<IfaceEvent<'_>>,
        tcp_stream_emitter: mpsc::UnboundedSender<TcpStream>,
    ) {
        while let Some(frame) = inbound.recv().await {
            let packet = match IpPacket::new_checked(frame.data()) {
                Ok(packet) => packet,
                Err(err) => {
                    warn!("Invalid packet: {err}");
                    continue;
                }
            };

            // Specially handle icmp packet by TCP interface.
            if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                match device_injector.send(frame) {
                    Ok(_) => {}
                    Err(err) => {
                        warn!("Failed to send packet to device: {err}");
                        continue;
                    }
                };
                match iface_notifier.send(IfaceEvent::Icmp) {
                    Ok(_) => continue,
                    Err(err) => {
                        warn!("Failed to send ICMP event: {err}");
                        continue;
                    }
                }
            }

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            let payload = packet.payload();

            let packet = match TcpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(err) => {
                    error!(
                        "invalid TCP err: {err}, src_ip: {src_ip}, dst_ip: \
                         {dst_ip}, payload: {payload:?}"
                    );
                    continue;
                }
            };
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            if packet.syn() && !packet.ack() {
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![
                        0u8;
                        DEFAULT_TCP_RECV_BUFFER_SIZE
                            as usize
                    ]),
                    tcp::SocketBuffer::new(vec![
                        0u8;
                        DEFAULT_TCP_SEND_BUFFER_SIZE
                            as usize
                    ]),
                );
                socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(28)));
                // FIXME: It should follow system's setting. 7200 is Linux's default.
                socket.set_timeout(Some(smoltcp::time::Duration::from_secs(7200)));
                // NO ACK delay
                socket.set_ack_delay(None);

                if let Err(err) = socket.listen(dst_addr) {
                    error!("listen error: {:?}", err);
                    continue;
                }

                trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);

                let handle = TcpStreamHandle {
                    recv_buffer: Arc::new(Protected::new(RingBuffer::new(
                        vec![0u8; DEFAULT_TCP_RECV_BUFFER_SIZE as usize],
                    ))),
                    send_buffer: Arc::new(Protected::new(RingBuffer::new(
                        vec![0u8; DEFAULT_TCP_SEND_BUFFER_SIZE as usize],
                    ))),
                };

                tcp_stream_emitter
                    .send(TcpStream {
                        local_addr: src_addr,
                        remote_addr: dst_addr,

                        handle: handle.clone(),
                    })
                    .map_err(|e| {
                        error!("Failed to send TCP stream: {}", e);
                    })
                    .ok();

                iface_notifier
                    .send(IfaceEvent::TcpStream((socket, handle)))
                    .map_err(|e| {
                        error!("Failed to send TCP stream event: {}", e);
                    })
                    .ok();
            }
        }
    }

    async fn poll_sockets(
        iface: &mut Interface,
        device: &mut NetstackDevice,
        mut notifier_rx: mpsc::UnboundedReceiver<IfaceEvent<'_>>,
    ) {
        // Create a socket set for TCP sockets
        let mut sockets = smoltcp::iface::SocketSet::new(vec![]);
        let mut socket_maps = HashMap::new();
        let mut next_poll = None;

        loop {
            tokio::select! {
                Some(event) = notifier_rx.recv() => {
                    match event {
                        IfaceEvent::Icmp => {
                            // Handle ICMP events if necessary
                        }
                        IfaceEvent::TcpStream((socket, handle)) => {
                            let socket_handle = sockets.add(socket);
                            socket_maps.insert(socket_handle, handle);
                            next_poll = None;
                        }
                    }
                },
                _ = match (next_poll, socket_maps.len()) {
                    (None, 0) => {
                        tokio::time::sleep(std::time::Duration::MAX)
                    },
                    (None, _) => {
                        tokio::time::sleep(std::time::Duration::ZERO)
                    },
                    (Some(dur), _) => {
                        tokio::time::sleep(dur)
                    }
                } => {
                    let now = smoltcp::time::Instant::now();
                    // Poll the interface for events
                    iface.poll(now, device, &mut sockets);

                    // Poll the sockets for new connections or data
                    for (socket_handle, socket_control) in socket_maps.iter() {
                        let socket = sockets.get_mut::<tcp::Socket>(*socket_handle);

                        if socket.can_recv() && !socket_control.recv_buffer.is_full() {
                            socket_control.recv_buffer.with_lock(|data| {
                                if socket
                                    .recv(|buffer| {
                                        let n = data.enqueue_slice(buffer);
                                        (n, ())
                                    })
                                    .is_ok()
                                {
                                    next_poll = None;
                                }
                            });
                        }
                        if socket.can_send() && !socket_control.send_buffer.is_empty() {
                            socket_control.send_buffer.with_lock(|data| {
                                if socket
                                    .send(|buffer| {
                                        let n = data.dequeue_slice(buffer);
                                        (n, ())
                                    })
                                    .is_ok()
                                {
                                    next_poll = None;
                                }
                            });
                        }
                    }

                    socket_maps.retain(|handle, _| {
                        let socket = sockets.get_mut::<tcp::Socket>(*handle);
                        if socket.is_active() {
                            true
                        } else {
                            trace!("Removing inactive TCP socket");
                            false
                        }
                    });

                    next_poll = match iface.poll_delay(now, &sockets) {
                        Some(smoltcp::time::Duration::ZERO) => None,
                        Some(delay) => {
                            trace!("device poll delay: {:?}", delay);
                            Some(delay.into())
                        }
                        None => None,
                    };
                }
            }
        }
    }
}

impl futures::Stream for TcpListener {
    type Item = TcpStream;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.socket_stream.try_recv() {
            Ok(stream) => std::task::Poll::Ready(Some(stream)),
            Err(_) => std::task::Poll::Pending,
        }
    }
}
