use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
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
use tracing::{error, trace, warn};

use super::{events::PortProtocol, ports::PortPool, stack::tcp::SocketPair};

pub struct DeviceManager {
    addr: IpAddr,

    unconnected_sockets:
        Arc<Mutex<Vec<(Socket<'static>, SocketAddr, Sender<Bytes>, Receiver<Bytes>)>>>,
    socket_set: Arc<Mutex<SocketSet<'static>>>,
    socket_pairs: Arc<Mutex<HashMap<SocketHandle, (Sender<Bytes>, Receiver<Bytes>)>>>,
    tcp_port_pool: PortPool,
}

impl DeviceManager {
    pub fn new(addr: IpAddr) -> Self {
        let unconnected_sockets = Arc::new(Mutex::new(Vec::new()));
        let socket_set = Arc::new(Mutex::new(SocketSet::new(Vec::new())));
        let socket_pairs = Arc::new(Mutex::new(HashMap::new()));
        let tcp_port_pool = PortPool::new();

        Self {
            addr,

            unconnected_sockets,
            socket_set,
            socket_pairs,
            tcp_port_pool,
        }
    }

    pub async fn new_tcp_socket(&self, remote: SocketAddr) -> SocketPair {
        let socket = Self::new_client_socket();
        let read_pair = tokio::sync::mpsc::channel(1024);
        let write_pair = tokio::sync::mpsc::channel(1024);
        self.unconnected_sockets
            .lock()
            .await
            .push((socket, remote, read_pair.0, write_pair.1));
        SocketPair::new(read_pair.1, write_pair.0)
    }

    pub async fn poll_sockets(&self, mut device: VirtualIpDevice) {
        let mut config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(self.addr.into(), 32)).unwrap();
        });

        loop {
            let mut need_wait = true;

            let timestamp = Instant::now();
            let mut sockets = self.socket_set.lock().await;
            let mut socket_pairs = self.socket_pairs.lock().await;

            let mut unconnected_sockets = self.unconnected_sockets.lock().await;
            let unconnected_sockets = unconnected_sockets.drain(0..);
            for (mut socket, remote, sender, receiver) in unconnected_sockets {
                socket
                    .connect(
                        iface.context(),
                        remote,
                        (self.addr, self.get_ephemeral_tcp_port().await),
                    )
                    .unwrap();

                let handle = sockets.add(socket);
                socket_pairs.insert(handle, (sender, receiver));

                need_wait = false;
            }

            iface.poll(timestamp, &mut device, &mut sockets);

            for (handle, (sender, receiver)) in socket_pairs.iter_mut() {
                let socket = sockets.get_mut::<tcp::Socket>(*handle);
                if socket.may_recv() {
                    match socket.recv(|data| (data.len(), data.to_owned())) {
                        Ok(data) if !data.is_empty() => match sender.try_send(data.into()) {
                            Ok(_) => {}
                            Err(e) => {
                                warn!("failed to send tcp packet: {:?}", e);
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
                    need_wait = false;
                }
                if socket.may_send() {
                    match receiver.try_recv() {
                        Ok(data) => match socket.send_slice(&data) {
                            Ok(n) => {
                                trace!("sent {} bytes, total: {}", n, data.len());
                                if n != data.len() {
                                    error!("fix me");
                                }
                            }
                            Err(e) => {
                                warn!("failed to send tcp packet: {:?}", e);
                            }
                        },
                        Err(_) => {}
                    }
                    need_wait = false;
                }
            }

            if need_wait {
                match iface.poll_delay(timestamp, &sockets) {
                    Some(delay) => {
                        trace!("device poll delay: {:?}", delay);
                        tokio::time::sleep(delay.into()).await;
                    }
                    None => {}
                }
            }

            let mut port_to_release = Vec::new();
            socket_pairs.retain(|handle, _| {
                let socket = sockets.get::<tcp::Socket>(*handle);
                if socket.is_open() {
                    true
                } else {
                    trace!("socket closed, shutting down connection: {:?}", socket);
                    let port = socket.local_endpoint().unwrap().port;
                    sockets.remove(*handle);
                    port_to_release.push(port);
                    false
                }
            });

            for port in port_to_release {
                self.release_ephemeral_tcp_port(port).await;
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
        packet_sender: Sender<Bytes>,
        packet_receiver: Receiver<(PortProtocol, Bytes)>,
        mtu: usize,
    ) -> Self {
        Self {
            mtu,
            packet_sender,
            packet_receiver,
        }
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(
        &mut self,
        timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let next = self.packet_receiver.try_recv().ok();
        match next {
            Some((proto, data)) => {
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

    fn transmit(&mut self, timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
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
