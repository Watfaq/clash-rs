use std::net::IpAddr;

use async_trait::async_trait;
use smoltcp::{
    iface::{Config, Interface},
    socket::tcp::Socket,
    time::Instant,
};

use crate::proxy::wg::{device::VirtualIpDevice, events::Bus};

use super::VirtualInterfacePoll;

pub struct VirtualTcpDevice {
    source_peer_ip: IpAddr,
    bus: Bus,
}

impl VirtualTcpDevice {
    pub fn new(source_peer_ip: IpAddr, bus: Bus) -> Self {
        Self {
            source_peer_ip,
            bus,
        }
    }

    pub fn new_client_socket() -> Socket<'static> {
        Socket::new(
            smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
            smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
        )
    }
}

#[async_trait]
impl VirtualInterfacePoll for VirtualTcpDevice {
    async fn poll_loop(self, device: VirtualIpDevice) -> std::io::Result<()> {
        let mut config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, Instant::now());
    }
}
