use std::{
    fmt::Debug,
    net::{IpAddr, SocketAddr},
};

use async_trait::async_trait;
use bytes::Bytes;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    socket::tcp::{self, RecvError, Socket},
    time::Instant,
    wire::IpCidr,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{Receiver, Sender},
};
use tracing::{trace, warn};

use crate::proxy::wg::device::VirtualIpDevice;

use super::VirtualInterfacePoll;

pub struct TcpSocketStack {
    source_peer_ip: IpAddr,
    remote_peer_endpoint: SocketAddr,

    socket: Socket<'static>,

    read_pair: (
        tokio::sync::broadcast::Sender<Bytes>,
        tokio::sync::broadcast::Receiver<Bytes>,
    ),
    write_pair: (Sender<Bytes>, Receiver<Bytes>),
}

#[derive(Debug)]
pub struct SocketPair {
    pub read: tokio::sync::broadcast::Receiver<Bytes>,
    pub write: Sender<Bytes>,
}

impl TcpSocketStack {
    pub fn new(source_peer_ip: IpAddr, remote_peer_ip: SocketAddr) -> Self {
        let socket = Self::new_client_socket();

        Self {
            source_peer_ip,
            remote_peer_endpoint: remote_peer_ip,
            socket,
            read_pair: tokio::sync::broadcast::channel(1024),
            write_pair: tokio::sync::mpsc::channel(1024),
        }
    }

    pub fn get_socket_pair(&self) -> SocketPair {
        SocketPair {
            read: self.read_pair.0.subscribe(),
            write: self.write_pair.0.clone(),
        }
    }

    fn new_client_socket() -> Socket<'static> {
        Socket::new(
            smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
            smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
        )
    }
}

impl AsyncRead for SocketPair {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.read.try_recv() {
            Ok(data) => {
                trace!("tcp socket received: {:?}", data);
                buf.put_slice(&data);
                std::task::Poll::Ready(Ok(()))
            }
            Err(_) => {
                trace!("no data ready");
                std::task::Poll::Pending
            }
        }
    }
}

impl AsyncWrite for SocketPair {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        #[allow(unused)] cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.write.try_send(buf.to_owned().into()) {
            Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
            Err(_) => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl VirtualInterfacePoll for TcpSocketStack {
    async fn poll_loop(self, mut device: VirtualIpDevice) -> std::io::Result<()> {
        let mut config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(self.source_peer_ip.into(), 32))
                .unwrap();
        });

        let mut sockets = SocketSet::new(vec![]);
        let tcp_handle = sockets.add(self.socket);

        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        let port = device.get_ephemeral_tcp_port().await;
        match socket.connect(
            iface.context(),
            self.remote_peer_endpoint,
            (self.source_peer_ip, port),
        ) {
            Ok(_) => {
                trace!("tcp socket connected");
            }
            Err(e) => {
                warn!("failed to connect tcp socket: {:?}", e);
            }
        }

        let mut incoming = self.write_pair.1;

        loop {
            let now = Instant::now();

            iface.poll(now, &mut device, &mut sockets);

            let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);

            if socket.may_recv() {
                match socket.recv(|data| (data.len(), data)) {
                    Ok(data) => {
                        trace!("tcp socket received: {:?}", data);
                        match self.read_pair.0.send(data.to_owned().into()) {
                            Ok(_) => {}
                            Err(e) => {
                                warn!("failed to send tcp packet: {:?}", e);
                            }
                        }
                    }
                    Err(RecvError::Finished) => {
                        warn!("tcp socket finished");
                        break;
                    }
                    Err(e) => {
                        warn!("failed to receive tcp packet: {:?}", e);
                    }
                }
            }

            if socket.may_send() {
                match incoming.try_recv() {
                    Ok(data) => {
                        trace!("tcp socket sending: {:?}", data);
                        match socket.send_slice(&data) {
                            Ok(_) => {}
                            Err(e) => {
                                warn!("failed to send tcp packet: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("failed to receive tcp packet: {:?}", e);
                    }
                }
            }

            if !socket.is_active() {
                trace!("socket closed");
                device.release_ephemeral_tcp_port(port).await;
                break;
            }

            match iface.poll_delay(now, &sockets) {
                Some(delay) => tokio::time::sleep(delay.into()).await,
                None => {}
            }
        }

        Ok(())
    }
}
