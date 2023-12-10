use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use async_recursion::async_recursion;
use boringtun::noise::{errors::WireGuardError, Tunn, TunnResult};

use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet};
use tokio::net::UdpSocket;
use tracing::{enabled, error, trace, warn};

use crate::Error;

use super::events::{Bus, Event, PortProtocol};

pub struct WireguardTunnel {
    pub(crate) source_peer_ip: IpAddr,
    peer: Box<Tunn>,
    udp: UdpSocket,
    pub(crate) endpoint: SocketAddr,
    bus: Bus,
}

pub struct Config {
    pub private_key: [u8; 32],
    pub endpoint_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub remote_endpoint: SocketAddr,
    pub source_peer_ip: IpAddr,
    pub keepalive_seconds: Option<u16>,
}

impl WireguardTunnel {
    pub async fn new(config: Config, bus: Bus) -> Result<Self, Error> {
        let source_peer_ip = config.source_peer_ip;
        let peer = Box::new(
            Tunn::new(
                config.private_key.into(),
                config.endpoint_public_key.into(),
                config.preshared_key,
                config.keepalive_seconds,
                0,
                None,
            )
            .map_err(|x| {
                Error::InvalidConfig(format!("failed to create wireguard tunnel: {}", x))
            })?,
        );

        let remote_endpoint = config.remote_endpoint;
        let udp = UdpSocket::bind("127.0.0.1:0").await?;

        Ok(Self {
            source_peer_ip,
            peer,
            udp,
            endpoint: remote_endpoint,
            bus,
        })
    }

    pub async fn send_ip_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        trace_ip_packet("Sending IP packet", packet);

        let mut send_buf = [0u8; 65535];
        match self.peer.encapsulate(packet, &mut send_buf) {
            boringtun::noise::TunnResult::Done => {}
            boringtun::noise::TunnResult::Err(e) => {
                error!("failed to encapsulate packet: {e:?}");
            }
            boringtun::noise::TunnResult::WriteToNetwork(packet) => {
                self.udp.send_to(&packet, self.endpoint).await?;
            }
            _ => {
                error!("unexpected result from encapsulate");
            }
        }
        Ok(())
    }

    pub async fn start_forwarding(&mut self) {
        let mut ep = self.bus.new_endpoint();

        loop {
            if let Event::OutboundInternetPacket(data) = ep.recv().await {
                if let Err(e) = self.send_ip_packet(&data).await {
                    error!("failed to send packet: {}", e);
                }
            }
        }
    }

    pub async fn start_heartbeat(&mut self) {
        loop {
            let mut send_buf = [0u8; 65535];
            let tun_result = self.peer.update_timers(&mut send_buf);
            self.handle_routine_result(tun_result).await;
        }
    }

    pub async fn start_receiving(&mut self) {
        let ep = self.bus.new_endpoint();

        loop {
            let mut recv_buf = [0u8; 65535];
            let mut send_buf = [0u8; 65535];

            let size = match self.udp.recv(&mut recv_buf).await {
                Ok(size) => size,
                Err(e) => {
                    error!("failed to receive packet: {e:?}");
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
            };

            let data = &recv_buf[..size];
            match self.peer.decapsulate(None, data, &mut send_buf) {
                TunnResult::Done => todo!(),
                TunnResult::Err(_) => todo!(),
                TunnResult::WriteToNetwork(packet) => {
                    match self.udp.send_to(&packet, self.endpoint).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("failed to send packet: {}", e);
                            continue;
                        }
                    }

                    loop {
                        let mut send_buf = [0u8; 65535];
                        match self.peer.decapsulate(None, &[], &mut send_buf) {
                            TunnResult::WriteToNetwork(packet) => {
                                match self.udp.send_to(packet, self.endpoint).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
                                        break;
                                    }
                                };
                            }
                            _ => {
                                break;
                            }
                        }
                    }
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    trace_ip_packet("Received IP packet", packet);

                    if let Some(proto) = self.route_protocol(packet) {
                        ep.send(Event::InboundInternetPacket(proto, packet.to_vec().into()));
                        // TODO: avoid copy
                    }
                }
            }
        }
    }

    #[async_recursion]
    async fn handle_routine_result<'a: 'async_recursion>(&mut self, result: TunnResult<'a>) {
        match result {
            TunnResult::Done => {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                warn!("wireguard connection expired");
                let mut buf = [0u8; 65535];
                let tun_result = self.peer.format_handshake_initiation(&mut buf[..], false);
                self.handle_routine_result(tun_result).await;
            }
            TunnResult::Err(e) => {
                error!("wireguard error: {e:?}");
            }
            TunnResult::WriteToNetwork(packet) => {
                match self.udp.send_to(&packet, self.endpoint).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("failed to send packet: {}", e);
                    }
                }
            }
            _ => {
                error!("unexpected result from wireguard");
            }
        }
    }

    /// Determine the inner protocol of the incoming IP packet (TCP/UDP).
    fn route_protocol(&self, packet: &[u8]) -> Option<PortProtocol> {
        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => Ipv4Packet::new_checked(&packet)
                .ok()
                // Only care if the packet is destined for this tunnel
                .filter(|packet| Ipv4Addr::from(packet.dst_addr()) == self.source_peer_ip)
                .and_then(|packet| match packet.next_header() {
                    IpProtocol::Tcp => Some(PortProtocol::Tcp),
                    IpProtocol::Udp => Some(PortProtocol::Udp),
                    // Unrecognized protocol, so we cannot determine where to route
                    _ => None,
                }),
            Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(&packet)
                .ok()
                // Only care if the packet is destined for this tunnel
                .filter(|packet| Ipv6Addr::from(packet.dst_addr()) == self.source_peer_ip)
                .and_then(|packet| match packet.next_header() {
                    IpProtocol::Tcp => Some(PortProtocol::Tcp),
                    IpProtocol::Udp => Some(PortProtocol::Udp),
                    // Unrecognized protocol, so we cannot determine where to route
                    _ => None,
                }),
            _ => None,
        }
    }
}

fn trace_ip_packet(message: &str, packet: &[u8]) {
    if enabled!(tracing::Level::TRACE) {
        use smoltcp::wire::*;

        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet)
            ),
            Ok(IpVersion::Ipv6) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet)
            ),
            _ => {}
        }
    }
}
