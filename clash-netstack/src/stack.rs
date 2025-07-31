use bytes::Bytes;

use log::debug;
use smoltcp::wire::IpProtocol;
use tokio::sync::mpsc;

use crate::{
    UdpSocket,
    debug::trace_ip_packet,
    packet::IpPacket,
    tcp_listener::{TcpListener, TcpStreamHandle},
};

pub(crate) enum IfaceEvent<'a> {
    Icmp, // ICMP packet received
    TcpStream((smoltcp::socket::tcp::Socket<'a>, TcpStreamHandle)), /* new TCP stream created */
    TcpSocketReady, // at least one TCP socket is ready to read/write
    DeviceReady,    // Device generated some packets
}
/// IO of the stack:
/// Sink to the stack with any IP packets
/// it will be demultiplexed to the correct protocol handler and each handler
/// will process the packets accordingly and write back to the stack Stream
/// Application can Stream the packets from the stack
pub struct NetStack {
    // where the packets get into UDP Stack
    udp_inbound: mpsc::UnboundedSender<Packet>,
    // inject TCP packets into the stack
    // where the packets get into TCP Stack
    tcp_inbound: mpsc::UnboundedSender<Packet>,

    // outside poll this to receive packets from the stack
    packet_outbound: mpsc::UnboundedReceiver<Packet>,
}

pub struct Packet {
    data: Bytes,
}

impl Packet {
    pub fn new(data: impl Into<Bytes>) -> Self {
        Packet { data: data.into() }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Bytes {
        self.data
    }
}

impl<T> From<T> for Packet
where
    T: Into<Bytes>,
{
    fn from(data: T) -> Self {
        Packet::new(data)
    }
}

impl NetStack {
    /// Returns the NetStack instance, a TcpListener and a UdpSocket
    pub fn new() -> (
        Self,
        crate::tcp_listener::TcpListener,
        crate::udp_socket::UdpSocket,
    ) {
        let (packet_sender, packet_receiver) = mpsc::unbounded_channel::<Packet>();

        let (udp_inbound_app, udp_outbound_stack) =
            mpsc::unbounded_channel::<Packet>();

        // this UdpSocket is essentially an Iface for UDP but much simpler as it only
        // does packets forwarding
        let udp_socket = UdpSocket::new(udp_outbound_stack, packet_sender.clone());
        let (tcp_inbound_app, tcp_outbound_stack) =
            mpsc::unbounded_channel::<Packet>();
        let tcp_listener =
            TcpListener::new(tcp_outbound_stack, packet_sender.clone());

        let stack = NetStack {
            udp_inbound: udp_inbound_app,
            tcp_inbound: tcp_inbound_app,
            packet_outbound: packet_receiver,
        };

        (stack, tcp_listener, udp_socket)
    }

    pub fn split(self) -> (StackSplitSink, StackSplitStream) {
        (
            StackSplitSink::new(self.udp_inbound, self.tcp_inbound),
            StackSplitStream::new(self.packet_outbound),
        )
    }
}

pub struct StackSplitSink {
    udp_inbound: mpsc::UnboundedSender<Packet>,
    tcp_inbound: mpsc::UnboundedSender<Packet>,

    packet_container: Option<(Packet, IpProtocol)>,
}
impl StackSplitSink {
    pub fn new(
        udp_inbound: mpsc::UnboundedSender<Packet>,
        tcp_inbound: mpsc::UnboundedSender<Packet>,
    ) -> Self {
        Self {
            udp_inbound,
            tcp_inbound,
            packet_container: None,
        }
    }
}
impl futures::Sink<Packet> for StackSplitSink {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.packet_container.is_none() {
            std::task::Poll::Ready(Ok(()))
        } else {
            std::task::Poll::Pending
        }
    }

    fn start_send(
        mut self: std::pin::Pin<&mut Self>,
        item: Packet,
    ) -> Result<(), Self::Error> {
        if item.data().is_empty() {
            return Ok(());
        }

        trace_ip_packet("tun inbound packet", item.data());

        let packet = IpPacket::new_checked(item.data())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let protocol = packet.protocol();
        if matches!(
            protocol,
            IpProtocol::Tcp
                | IpProtocol::Udp
                | IpProtocol::Icmp
                | IpProtocol::Icmpv6
        ) {
            self.packet_container.replace((item, protocol));
        } else {
            debug!("tun IP packet ignored (protocol: {protocol:?})");
        }

        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let (item, proto) = match self.packet_container.take() {
            Some(val) => val,
            None => return std::task::Poll::Ready(Ok(())),
        };

        match proto {
            IpProtocol::Udp => match self.udp_inbound.send(item) {
                Ok(()) => {}
                Err(e) => {
                    debug!("Failed to send UDP packet: {e}");
                    self.packet_container = Some((e.0, proto));
                }
            },
            IpProtocol::Tcp | IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                self.tcp_inbound.send(item).map_err(|e| {
                    debug!("Failed to send TCP packet: {e}");
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
                })?;
            }
            _ => {
                debug!("Unsupported protocol for packet: {proto:?}");
            }
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

pub struct StackSplitStream {
    packet_outbound: mpsc::UnboundedReceiver<Packet>,
}
impl StackSplitStream {
    pub fn new(packet_outbound: mpsc::UnboundedReceiver<Packet>) -> Self {
        Self { packet_outbound }
    }
}
impl futures::Stream for StackSplitStream {
    type Item = std::io::Result<Packet>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.packet_outbound.poll_recv(cx) {
            std::task::Poll::Ready(Some(packet)) => {
                trace_ip_packet("tun reply packet", packet.data());
                std::task::Poll::Ready(Some(Ok(packet)))
            }
            std::task::Poll::Ready(None) => {
                std::task::Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Tun stream closed",
                ))))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
