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
    time::Duration,
};
use tokio::sync::mpsc;

const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = 256 * 1024; // 512 KB
const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = 256 * 1024; // 512 KB

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
    socket_stream_waker: Arc<AtomicWaker>,

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
        outbound: mpsc::Sender<Packet>,
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

        let socket_stream_waker = Arc::new(AtomicWaker::new());

        let waker = socket_stream_waker.clone();
        let task_handle = tokio::spawn(async move {
            let rv = tokio::select! {
                biased;
                rv = Self::poll_packets(inbound, device.create_injector(), iface_notifier, socket_stream_emitter, waker) => rv,
                rv = Self::poll_sockets(&mut iface, &mut device, iface_notifier_rx) => rv,
            };
            if let Err(e) = rv {
                error!("Error in TCP listener: {e}");
            }
        });

        TcpListener {
            socket_stream,
            task_handle,
            socket_stream_waker,
        }
    }

    async fn poll_packets(
        mut inbound: mpsc::UnboundedReceiver<Packet>,
        device_injector: mpsc::UnboundedSender<Packet>,
        iface_notifier: mpsc::UnboundedSender<IfaceEvent<'static>>,
        tcp_stream_emitter: mpsc::UnboundedSender<TcpStream>,
        tcp_stream_waker: Arc<AtomicWaker>,
    ) -> std::io::Result<()> {
        let mut packet_buf = Vec::with_capacity(32);
        while let n = inbound.recv_many(&mut packet_buf, 32).await
            && n > 0
        {
            trace!("Received {n} packets from inbound channel");
            for frame in packet_buf.drain(..) {
                let packet = match IpPacket::new_checked(frame.data()) {
                    Ok(packet) => packet,
                    Err(err) => {
                        warn!("Invalid packet: {err}");
                        continue;
                    }
                };

                // Specially handle icmp packet by TCP interface.
                if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6)
                {
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
                    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(
                        28,
                    )));

                    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
                        if cfg!(target_os = "linux") { 7200 } else { 60 },
                    )));
                    // Default
                    socket.set_ack_delay(Some(Duration::from_millis(10).into()));
                    socket.set_nagle_enabled(false);
                    socket.set_congestion_control(tcp::CongestionControl::Cubic);

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
                    tcp_stream_waker.wake();
                }

                device_injector.send(frame).map_err(|e| {
                    error!("Failed to send packet to device: {e}");
                    std::io::Error::other("Failed to inject packet to device")
                })?;
            }

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
        let mut socket_maps: HashMap<
            smoltcp::iface::SocketHandle,
            Arc<TcpStreamHandle>,
        > = HashMap::new();
        let mut next_poll = None;

        loop {
            trace!(
                "Polling TCP sockets, next_poll: {:?}, num of sockets: {}",
                next_poll,
                socket_maps.len()
            );

            let should_poll_now = match (next_poll, socket_maps.len()) {
                (None, 0) => {
                    trace!("No sockets to poll, waiting indefinitely");
                    false
                }
                (None, _) => {
                    trace!("Polling sockets with no delay");
                    true
                }
                (Some(dur), _) => {
                    trace!("Polling sockets with delay: {dur:?}");
                    false
                }
            };
            let now = smoltcp::time::Instant::now();

            if should_poll_now {
                trace!("Woke up to poll sockets");

                iface.poll(now, device, &mut sockets);

                // Poll the sockets for new connections or data
                for (socket_handle, socket_control) in socket_maps.iter() {
                    let socket = sockets.get_mut::<tcp::Socket>(*socket_handle);
                    trace!(
                        "Polling TCP socket: {:?}, can_recv: {}, can_send: {}",
                        socket_handle,
                        socket.can_recv(),
                        socket.can_send()
                    );

                    let buf = &socket_control.recv_buffer;
                    let mut notify_read = false;
                    while socket.can_recv() && !buf.is_full() {
                        if let Ok(n) = socket.recv(|buffer| {
                            let n = buf.enqueue_slice(buffer);
                            (n, n)
                        }) {
                            trace!("Received {n} bytes from TCP socket");
                        }
                        notify_read = true;
                    }
                    if notify_read {
                        socket_control.recv_waker.wake();
                    }

                    let buf = &socket_control.send_buffer;
                    let mut notify_write = false;
                    while socket.can_send() && !buf.is_empty() {
                        if let Ok(n) = socket.send(|buffer| {
                            let n = buf.dequeue_slice(buffer);
                            (n, n)
                        }) {
                            trace!("Sent {n} bytes to TCP socket");
                        }
                        notify_write = true;
                    }

                    if notify_write {
                        socket_control.send_waker.wake();
                    }
                }

                socket_maps.retain(|handle, socket_control| {
                    if socket_control
                        .socket_dropped
                        .load(std::sync::atomic::Ordering::Acquire)
                    {
                        trace!("Removing dropped TCP socket");
                        sockets.remove(*handle);
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
            } else {
                tokio::select! {
                    Some(event) = notifier_rx.recv() => {
                        trace!("Received iface event, will poll sockets");
                        next_poll = None; // reset the next poll time
                        match event {
                            IfaceEvent::TcpStream(stream) => {
                                let socket_handle = sockets.add(stream.0);
                                socket_maps.insert(socket_handle, stream.1);
                                trace!("Added new TCP socket: {socket_handle:?}");
                            }
                            IfaceEvent::TcpSocketReady => {
                                trace!("TCP socket is ready to read/write");
                            }
                            IfaceEvent::TcpSocketClosed => {
                                trace!("TCP socket closed by application");
                            }
                            IfaceEvent::DeviceReady => {
                                trace!("Device generated some packets, will poll sockets");
                            }
                            IfaceEvent::Icmp => {
                                trace!("ICMP packet received, will poll sockets");
                            }
                        }
                    }
                    _ = tokio::time::sleep(next_poll.unwrap_or(Duration::MAX)) => {
                        trace!("Woke up to poll sockets after delay");
                        next_poll = None; // reset the next poll time
                    }
                }
            }
        }
    }
}

impl futures::Stream for TcpListener {
    type Item = TcpStream;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.socket_stream.try_recv() {
            Ok(stream) => std::task::Poll::Ready(Some(stream)),
            Err(e) => match e {
                mpsc::error::TryRecvError::Empty => {
                    self.socket_stream_waker.register(cx.waker());
                    std::task::Poll::Pending
                }
                mpsc::error::TryRecvError::Disconnected => {
                    std::task::Poll::Ready(None)
                }
            },
        }
    }
}
