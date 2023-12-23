use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::tcp::{self, RecvError, Socket},
    time::Instant,
    wire::IpCidr,
};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};
use tracing::{error, trace, trace_span, warn, Instrument};

use super::{events::PortProtocol, ports::PortPool, stack::tcp::SocketPair};

pub struct DeviceManager {
    addr: IpAddr,

    socket_set: Arc<Mutex<SocketSet<'static>>>,
    socket_pairs: Arc<Mutex<HashMap<SocketHandle, Sender<Bytes>>>>,
    tcp_port_pool: PortPool,

    packet_notifier: Arc<Mutex<Receiver<()>>>,

    socket_notifier: Sender<(Socket<'static>, SocketAddr, Sender<Bytes>, Receiver<Bytes>)>,
    socket_notifier_receiver:
        Arc<Mutex<Receiver<(Socket<'static>, SocketAddr, Sender<Bytes>, Receiver<Bytes>)>>>,
}

impl DeviceManager {
    pub fn new(addr: IpAddr, packet_notifier: Receiver<()>) -> Self {
        let socket_set = Arc::new(Mutex::new(SocketSet::new(Vec::new())));
        let socket_pairs = Arc::new(Mutex::new(HashMap::new()));
        let tcp_port_pool = PortPool::new();

        let (socket_notifier, socket_notifier_receiver) = tokio::sync::mpsc::channel(1024);

        Self {
            addr,

            socket_set,
            socket_pairs,
            tcp_port_pool,

            packet_notifier: Arc::new(Mutex::new(packet_notifier)),

            socket_notifier,
            socket_notifier_receiver: Arc::new(Mutex::new(socket_notifier_receiver)),
        }
    }

    pub async fn new_tcp_socket(&self, remote: SocketAddr) -> SocketPair {
        let socket = Self::new_client_socket();
        let read_pair = tokio::sync::mpsc::channel(1024);
        let write_pair = tokio::sync::mpsc::channel(1024);

        self.socket_notifier
            .send((socket, remote, read_pair.0, write_pair.1))
            .await
            .unwrap();
        SocketPair::new(read_pair.1, write_pair.0)
    }

    pub async fn poll_sockets(&self, mut device: VirtualIpDevice) {
        let mut config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(self.addr.into(), 32)).unwrap();
        });

        let (device_sender, mut device_receiver) = tokio::sync::mpsc::channel(1024);
        let mut send_queue: HashMap<SocketHandle, VecDeque<(Bytes, bool)>> = HashMap::new();
        let mut next_poll = None;

        loop {
            let mut sockets = self.socket_set.lock().await;
            let mut socket_pairs = self.socket_pairs.lock().await;

            let mut packet_notifier = self.packet_notifier.lock().await;
            let mut socket_notifier_receiver = self.socket_notifier_receiver.lock().await;

            tokio::select! {
                Some((mut socket, remote, sender, mut receiver)) = socket_notifier_receiver.recv() => {
                    trace!("got new socket, notifying to poll sockets");
                    socket
                    .connect(
                        iface.context(),
                        remote,
                        (self.addr, self.get_ephemeral_tcp_port().await),
                    )
                    .unwrap();

                    let handle = sockets.add(socket);
                    let device_sender = device_sender.clone();
                    tokio::spawn(async move {
                        loop {
                            let data = match receiver.recv().await {
                                Some(data) => data,
                                None => {
                                    break;
                                }
                            };
                            trace!("sending {} bytes", data.len());
                            device_sender.send((handle, data, true)).await.unwrap();
                        }
                        trace!("socket {} closed, sending close signal", handle);
                        device_sender
                            .send((handle, Vec::new().into(), false))
                            .await
                            .unwrap();
                    });

                    socket_pairs.insert(handle, sender);
                    send_queue.insert(handle, VecDeque::new());

                    next_poll = None;
                }

                _ = packet_notifier.recv() => {
                    trace!("lower layer packet received, polling sockets");
                    next_poll = None;
                }

                Some((handle, data, active)) = device_receiver.recv() => {
                    if let Some(queue) = send_queue.get_mut(&handle) {
                        trace!("socket {} has {} data to send", handle, data.len());
                        queue.push_back((data, active));
                        next_poll = None;
                    }
                }

                _ = match (next_poll, socket_pairs.len()) {
                    (None, 0) => {
                        tokio::time::sleep(Duration::MAX)
                    },
                    (None, _) => {
                        tokio::time::sleep(Duration::ZERO)
                    },
                    (Some(dur), _) => {
                        tokio::time::sleep(dur)
                    }
                } => {
                    let _ = trace_span!("poll_sockets").enter();

                    let timestamp = Instant::now();
                    iface.poll(timestamp, &mut device, &mut sockets);

                    for (handle, sender) in socket_pairs.iter_mut() {
                        let socket = sockets.get_mut::<tcp::Socket>(*handle);
                        if socket.may_recv() {
                            match socket.recv(|data| (data.len(), data.to_owned())) {
                                Ok(data) if !data.is_empty() => match sender.try_send(data.into()) {
                                    Ok(_) => {}
                                    Err(_) => {
                                        trace!("socket {} closed from remote(?), aboring connection", handle);
                                        socket.abort();
                                    }
                                },
                                Ok(_) => {}
                                Err(RecvError::Finished) => {
                                    warn!("tcp socket finished");
                                    continue;
                                }
                                Err(e) => {
                                    warn!("failed to receive tcp packet: {:?}", e);
                                }
                            }
                        }

                        if socket.may_send() {
                            if let Some(queue) = send_queue.get_mut(handle) {
                                let data = queue.pop_front();
                                if let Some((to_transfer_slice, active)) = data {
                                    if !active {
                                        trace!("socket {} closed from local(?), aboring socket", handle);
                                        socket.abort();
                                    } else {
                                        let total = to_transfer_slice.len();
                                        trace!("socket {} sending {} bytes", handle, total);
                                        match socket.send_slice(&to_transfer_slice) {
                                            Ok(sent) => {
                                                if sent < total {
                                                    // Sometimes only a subset is sent, so the rest needs to be sent on the next poll
                                                    let tx_extra = Vec::from(&to_transfer_slice[sent..total]);
                                                    queue.push_front((tx_extra.into(), true));
                                                }
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Failed to send slice via virtual client socket: {:?}",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    // the local side has closed, but we don't know if the remote should be closed
                                    // let the dispatcher timeout to close the connection
                                }
                            }
                        }
                    }

                    let mut port_to_release = Vec::new();
                    socket_pairs.retain(|handle, _| {
                        let socket = sockets.get::<tcp::Socket>(*handle);
                        if socket.is_active() {
                            true
                        } else {
                            trace!("socket {} closed, shutting down connection and releasing resources", handle);
                            let port = socket.local_endpoint().unwrap().port;
                            sockets.remove(*handle);
                            send_queue.remove(handle);
                            port_to_release.push(port);
                            false
                        }
                    });

                    for port in port_to_release {
                        self.release_ephemeral_tcp_port(port).await;
                    }

                    next_poll = match iface.poll_delay(timestamp, &sockets) {
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

    async fn get_ephemeral_tcp_port(&self) -> u16 {
        self.tcp_port_pool.next().await.unwrap()
    }

    async fn release_ephemeral_tcp_port(&self, port: u16) {
        self.tcp_port_pool.release(port).await;
    }

    fn new_client_socket() -> Socket<'static> {
        Socket::new(
            smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
            smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
        )
    }
}

pub struct VirtualIpDevice {
    mtu: usize,

    packet_sender: Sender<Bytes>,
    packet_receiver: Receiver<(PortProtocol, Bytes)>,
}

impl VirtualIpDevice {
    pub fn new(
        // send packet to wg stack
        packet_sender: Sender<Bytes>,
        // when wg stack receives a packet, it will send it to this receiver
        mut packet_receiver: Receiver<(PortProtocol, Bytes)>,

        // when wg stack receives a packet, it will send a notification to this sender
        packet_notifier: Sender<()>,
        mtu: usize,
    ) -> Self {
        let (inner_packet_sender, inner_packet_receiver) = tokio::sync::mpsc::channel(1024);
        tokio::spawn(async move {
            loop {
                let span = trace_span!("receive_packet");

                if let Some((proto, data)) = packet_receiver.recv().instrument(span).await {
                    inner_packet_sender.send((proto, data)).await.unwrap();
                    let _ = packet_notifier.try_send(());
                } else {
                    break;
                }
            }
        });

        Self {
            mtu,
            packet_sender,
            packet_receiver: inner_packet_receiver,
        }
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let next = self.packet_receiver.try_recv().ok();
        match next {
            Some((_proto, data)) => {
                let rx_token = RxToken {
                    buffer: {
                        let mut buffer = BytesMut::new();
                        buffer.put(data);
                        buffer
                    },
                };
                let tx_token = TxToken {
                    sender: self.packet_sender.clone(),
                };
                Some((rx_token, tx_token))
            }
            None => None,
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            sender: self.packet_sender.clone(),
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct RxToken {
    buffer: BytesMut,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

pub struct TxToken {
    sender: Sender<Bytes>,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        match self.sender.try_send(buffer.into()) {
            Ok(_) => {}
            Err(err) => {
                error!("failed to send packet: {}", err);
            }
        }
        result
    }
}
