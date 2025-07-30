use crate::{Packet, packet::IpPacket};
use etherparse::PacketBuilder;
use log::{error, trace};
use std::net::SocketAddr;
use tokio::sync::mpsc;

pub struct UdpPacket {
    pub data: Packet,
    /// src of the packet
    pub local_addr: SocketAddr,
    /// dst of the packet
    pub remote_addr: SocketAddr,
}
impl std::fmt::Debug for UdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("data_len", &self.data().len())
            .finish()
    }
}

impl UdpPacket {
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

pub struct UdpSocket {
    inbound: mpsc::UnboundedReceiver<Packet>,
    outbound: mpsc::UnboundedSender<Packet>,
}

impl UdpSocket {
    pub fn new(
        inbound: mpsc::UnboundedReceiver<Packet>,
        outbound: mpsc::UnboundedSender<Packet>,
    ) -> Self {
        Self { inbound, outbound }
    }

    pub fn split(self) -> (SplitRead, SplitWrite) {
        let read = SplitRead { recv: self.inbound };
        let write = SplitWrite {
            send: self.outbound,
        };
        (read, write)
    }
}

pub struct SplitRead {
    recv: mpsc::UnboundedReceiver<Packet>,
}

impl SplitRead {
    pub async fn recv(&mut self) -> Option<UdpPacket> {
        self.recv.recv().await.and_then(|data| {
            let packet = match IpPacket::new_checked(data.data()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid IP packet: {}", err);
                    return None;
                }
            };

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            let payload = packet.payload();

            let packet = match smoltcp::wire::UdpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(err) => {
                    error!(
                        "invalid err: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, \
                         payload: {payload:?}"
                    );
                    return None;
                }
            };
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            trace!("created UDP socket for {} <-> {}", src_addr, dst_addr);

            Some(UdpPacket {
                data: Packet::new(packet.payload().to_vec()),
                local_addr: src_addr,
                remote_addr: dst_addr,
            })
        })
    }
}

#[derive(Clone)]
pub struct SplitWrite {
    send: mpsc::UnboundedSender<Packet>,
}

impl SplitWrite {
    pub async fn send(&mut self, packet: UdpPacket) -> Result<(), std::io::Error> {
        if packet.data.data().is_empty() {
            return Ok(());
        }

        let builder = match (packet.local_addr, packet.remote_addr) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 20)
                    .udp(src.port(), dst.port())
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP socket only supports IPv4 and IPv6",
                ));
            }
        };

        let mut ip_packet_writer =
            Vec::with_capacity(builder.size(packet.data.data().len()));
        builder
            .write(&mut ip_packet_writer, &packet.data.data())
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        match self.send.send(Packet::new(ip_packet_writer)) {
            Ok(()) => Ok(()),
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("send error: {err}"),
            )),
        }
    }
}
