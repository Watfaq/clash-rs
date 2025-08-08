use crate::{
    Packet, device::NetstackDevice, packet::IpPacket,
    ring_buffer::LockFreeRingBuffer, stack::IfaceEvent, tcp_stream::TcpStream,
};
use futures::task::AtomicWaker;
use log::{error, trace, warn};
use smoltcp::{
    iface::Interface,
    socket::tcp,
    wire::{IpProtocol, TcpPacket},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, atomic::AtomicBool},
};
use tokio::sync::mpsc;

// NOTE: Default buffer could contain 20 AEAD packets
const AEAD_PACKET_SIZE: u32 = 0x3FFF; // Base size of an AEAD packet (16,383 bytes)
const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = AEAD_PACKET_SIZE * 20; // Buffer for 20 AEAD packets
const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = AEAD_PACKET_SIZE * 20; // Buffer for 20 AEAD packets

pub(crate) struct TcpStreamHandle {
    pub(crate) recv_buffer: LockFreeRingBuffer,
    pub(crate) recv_waker: AtomicWaker,
    pub(crate) send_buffer: LockFreeRingBuffer,
    pub(crate) send_waker: AtomicWaker,

    pub(crate) socket_dropped: AtomicBool,
}

impl TcpStreamHandle {
    pub fn new() -> Self {
        Self {
            recv_buffer: LockFreeRingBuffer::new(
                DEFAULT_TCP_RECV_BUFFER_SIZE as usize,
            ),
            recv_waker: AtomicWaker::new(),
            send_buffer: LockFreeRingBuffer::new(
                DEFAULT_TCP_SEND_BUFFER_SIZE as usize,
            ),
            send_waker: AtomicWaker::new(),
            socket_dropped: AtomicBool::new(false),
        }
    }
}

impl Drop for TcpStreamHandle {
    fn drop(&mut self) {
        trace!("TcpStreamHandle dropped");
    }
}

pub struct TcpListener {
    socket_stream: mpsc::UnboundedReceiver<TcpStream>,

    task_handle: tokio::task::JoinHandle<()>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        trace!("TcpListener dropped");
        self.task_handle.abort();
    }
}

impl TcpListener {
    pub fn new(
        inbound: mpsc::UnboundedReceiver<Packet>,
        outbound: mpsc::UnboundedSender<Packet>,
    ) -> Self {
        // the global bus that drives the iface polling
        let (iface_notifier, iface_notifier_rx) = mpsc::unbounded_channel();

        let mut config =
            smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut device = NetstackDevice::new(outbound, iface_notifier.clone());
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

        iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1))
            .expect("Failed to add default IPv4 route");
        iface
            .routes_mut()
            .add_default_ipv6_route(smoltcp::wire::Ipv6Address::new(
                0x0, 0xfac, 0, 0, 0, 0, 0, 1,
            ))
            .expect("Failed to add default IPv6 route");

        let (socket_stream_emitter, socket_stream) =
            mpsc::unbounded_channel::<TcpStream>();

        let task_handle = tokio::spawn(async move {
            let rv = tokio::select! {
                biased;
                rv = Self::poll_packets(inbound, device.create_injector(), iface_notifier, socket_stream_emitter) => rv,
                rv = Self::poll_sockets(&mut iface, &mut device, iface_notifier_rx) => rv,
            };
            if let Err(e) = rv {
                error!("Error in TCP listener: {e}");
            }
        });

        TcpListener {
            socket_stream,
            task_handle,
        }
    }

    async fn poll_packets(
        mut inbound: mpsc::UnboundedReceiver<Packet>,
        device_injector: mpsc::UnboundedSender<Packet>,
        iface_notifier: mpsc::UnboundedSender<IfaceEvent<'static>>,
        tcp_stream_emitter: mpsc::UnboundedSender<TcpStream>,
    ) -> std::io::Result<()> {
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
                socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
                    if cfg!(target_os = "linux") { 7200 } else { 60 },
                )));
                // NO ACK delay
                socket.set_ack_delay(None);

                if let Err(err) = socket.listen(dst_addr) {
                    error!("listen error: {err:?}");
                    continue;
                }

                trace!("created TCP connection for {src_addr} <-> {dst_addr}");

                let handle = Arc::new(TcpStreamHandle::new());

                tcp_stream_emitter
                    .send(TcpStream {
                        local_addr: src_addr,
                        remote_addr: dst_addr,

                        handle: handle.clone(),
                        stack_notifier: iface_notifier.clone(),
                    })
                    .map_err(|e| {
                        error!("Failed to send TCP stream: {e}");
                        std::io::Error::other("Failed to send TCP stream")
                    })?;
                iface_notifier
                    .send(IfaceEvent::TcpStream(Box::new((socket, handle))))
                    .map_err(|e| {
                        error!("Failed to send TCP stream event: {e}");
                        std::io::Error::other("Failed to send TCP stream event")
                    })?;
            }

            device_injector.send(frame).map_err(|e| {
                error!("Failed to send packet to device: {e}");
                std::io::Error::other("Failed to inject packet to device")
            })?;
            // trigger another poll to drive the socket state machine
            iface_notifier.send(IfaceEvent::DeviceReady).map_err(|e| {
                error!("Failed to send device ready event: {e}");
                std::io::Error::other("Failed to send device ready event")
            })?;
        }
        Ok(())
    }

    async fn poll_sockets(
        iface: &mut Interface,
        device: &mut NetstackDevice,
        mut notifier_rx: mpsc::UnboundedReceiver<IfaceEvent<'_>>,
    ) -> std::io::Result<()> {
        // Create a socket set for TCP sockets
        let mut sockets = smoltcp::iface::SocketSet::new(vec![]);
        let mut socket_maps = HashMap::new();
        let mut next_poll = None;

        loop {
            trace!(
                "Polling TCP sockets, next_poll: {:?}, num of sockets: {}",
                next_poll,
                socket_maps.len()
            );
            tokio::select! {
                biased;
                Some(event) = notifier_rx.recv() => {
                    trace!("Received iface event: {:?}", event);
                    match event {
                        IfaceEvent::Icmp => {
                            trace!("Received ICMP event");
                            next_poll = None;
                        }
                        IfaceEvent::TcpStream(boxed) => {
                            let (socket, handle) = *boxed;
                            let socket_handle = sockets.add(socket);
                            socket_maps.insert(socket_handle, handle);
                            next_poll = None;
                        }
                        IfaceEvent::TcpSocketReady | IfaceEvent::TcpSocketClosed => {
                            trace!("TCP socket ready or closed event");
                            next_poll = None;
                        }
                        IfaceEvent::DeviceReady => {
                            trace!("Device is ready, has some packets to process");
                            next_poll = None;
                        }
                    }
                },
                _ = match (next_poll, socket_maps.len()) {
                    (None, 0) => {
                        trace!("No sockets to poll, waiting indefinitely");
                        tokio::time::sleep(std::time::Duration::MAX)
                    },
                    (None, _) => {
                        trace!("Polling sockets with no delay");
                        tokio::time::sleep(std::time::Duration::ZERO)
                    },
                    (Some(dur), _) => {
                        trace!("Polling sockets with delay: {:?}", dur);
                        tokio::time::sleep(dur)
                    }
                } => {
                    trace!("Woke up to poll sockets");
                    let now = smoltcp::time::Instant::now();
                    // Poll the interface for events
                    iface.poll(now, device, &mut sockets);

                    // Poll the sockets for new connections or data
                    for (socket_handle, socket_control) in socket_maps.iter() {
                        let socket = sockets.get_mut::<tcp::Socket>(*socket_handle);
                        trace!("Polling TCP socket: {:?}, can_recv: {}, can_send: {}", socket_handle, socket.can_recv(), socket.can_send());

                        if socket.can_recv() {
                            let buf = &socket_control.recv_buffer;

                            if !buf.is_full() {
                                if let Ok(n) = socket
                                    .recv(|buffer| {
                                        let n = buf.enqueue_slice(buffer);
                                        (n, n)
                                    })

                                {
                                    trace!("Received {n} bytes from TCP socket");
                                }
                            } else {
                                trace!("TCP socket recv buffer is full, skipping recv");
                            }

                            socket_control.recv_waker.wake();
                        }

                        if socket.can_send() {
                            let buf = &socket_control.send_buffer;

                            if !buf.is_empty() {
                                if let Ok(n) = socket
                                    .send(|buffer| {
                                        let n = buf.dequeue_slice(buffer);
                                        (n, n)
                                    })

                                {
                                    trace!("Sent {n} bytes to TCP socket");
                                }
                            } else {
                                trace!("TCP socket send buffer is empty, skipping send");
                            }
                            socket_control.send_waker.wake();

                        }
                    }

                    socket_maps.retain(|handle, socket_control| {
                        if socket_control.socket_dropped.load(std::sync::atomic::Ordering::Acquire) {
                            trace!("Removing dropped TCP socket");
                            return false;
                        }

                        let socket = sockets.get_mut::<tcp::Socket>(*handle);
                        if socket.is_active() {
                            true
                        } else {
                            trace!("Removing inactive TCP socket");
                            sockets.remove(*handle);
                            false
                        }
                    });

                    next_poll = match iface.poll_delay(now, &sockets) {
                        Some(smoltcp::time::Duration::ZERO) => None,
                        Some(delay) => {
                            trace!("device poll delay: {delay:?}");
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
