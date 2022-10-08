use crate::dns::dns_client::DNSNetMode;
use crate::dns::{Client, NameServer, Resolver, ThreadSafeDNSClient};
use crate::proxy::utils::{new_udp_socket, Interface};
use crate::Error;
use async_trait::async_trait;
use dhcproto::{Decodable, Encodable};
use futures::lock::Mutex;
use ipnet::IpBitAnd;
use libc::{getifaddrs, malloc};
use log::debug;
use network_interface::{Addr, NetworkInterfaceConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Add;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{env, io, mem};
use tokio::net::UdpSocket;
use trust_dns_proto::op::Message;

const IFACE_TTL: Duration = Duration::from_secs(20);
const DHCP_TTL: Duration = Duration::from_secs(3600);
const DHCP_TIMEOUT: Duration = Duration::from_secs(60);

pub struct DhcpClient {
    iface: String,

    iface_addr: ipnet::IpNet,

    clients: Vec<ThreadSafeDNSClient>,
    iface_expires_at: std::time::Instant,
    dns_expires_at: std::time::Instant,
}

#[async_trait]
impl Client for DhcpClient {
    async fn exchange(&mut self, msg: &Message) -> anyhow::Result<Message> {
        let clients = self.resolve().await?;
        tokio::time::timeout(DHCP_TIMEOUT, Resolver::batch_exchange(clients, msg)).await?
    }
}

impl DhcpClient {
    pub fn new(iface: &str) -> Self {
        Self {
            iface: iface.to_owned(),
            iface_addr: ipnet::IpNet::default(),
            clients: vec![],
            iface_expires_at: Instant::now(),
            dns_expires_at: Instant::now(),
        }
    }

    async fn resolve(&mut self) -> io::Result<&Vec<ThreadSafeDNSClient>> {
        let expired = self.lease_expired()?;
        if expired {
            let dns = unsafe { probe_dns_server(&self.iface).await? };
            self.clients = Resolver::make_clients(
                dns.into_iter()
                    .map(|s| NameServer {
                        net: DNSNetMode::UDP,
                        address: format!("{}:53", s.to_string()),
                        interface: None,
                    })
                    .collect(),
                None,
            )
            .await;
        }

        Ok(&self.clients)
    }

    /// Check if interface updated or DHCP changed
    /// and update if necessary
    fn lease_expired(&mut self) -> io::Result<bool> {
        if Instant::now() < self.iface_expires_at {
            return Ok(false);
        }

        self.iface_expires_at = Instant::now().add(IFACE_TTL);

        let iface = network_interface::NetworkInterface::show()
            .map_err(|x| io::Error::new(io::ErrorKind::Other, format!("list ifaces: {:?}", x)))?
            .into_iter()
            .find(|x| {
                debug!("iface: {}, {:?}", x.name, x.addr);
                x.name == self.iface && x.addr.map(|x| x.ip().is_ipv4()).unwrap_or(false)
            })
            .ok_or(io::Error::new(
                io::ErrorKind::Other,
                format!("can not find interface: {}", self.iface),
            ))?;

        let addr = iface.addr.ok_or(io::Error::new(
            io::ErrorKind::Other,
            format!("no address on interface: {}", self.iface),
        ))?;

        match addr {
            Addr::V4(v4) => {
                if Instant::now() < self.dns_expires_at
                    && self.iface_addr.addr() == v4.ip
                    && self.iface_addr.netmask()
                        == v4.netmask.ok_or(io::Error::new(
                            io::ErrorKind::Other,
                            format!("no netmask on iface: {}", self.iface),
                        ))?
                {
                    Ok(false)
                } else {
                    self.dns_expires_at = Instant::now().add(DHCP_TTL);
                    self.iface_addr = ipnet::IpNet::new(
                        v4.ip.into(),
                        u32::from(
                            v4.netmask
                                .ok_or(io::Error::new(io::ErrorKind::Other, "no netmask"))?,
                        )
                        .count_ones() as _,
                    )
                    .map_err(|x| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!(
                                "invalid netmask: {}",
                                v4.netmask.expect("expect netmask parse error")
                            ),
                        )
                    })?;
                    Ok(true)
                }
            }
            Addr::V6(_) => unreachable!("should only run on V4"),
        }
    }
}

async fn listen_dhcp_client(iface: &str) -> io::Result<UdpSocket> {
    let listen_addr = match env::consts::OS {
        "linux" | "android" => "0.0.0.0:68",
        _ => "255.255.255.255:68",
    };

    new_udp_socket(
        &listen_addr.parse().expect("must parse"),
        Some(&Interface::Name(iface.to_string())),
    )
    .await
}

async unsafe fn probe_dns_server(iface: &str) -> io::Result<Vec<Ipv4Addr>> {
    let socket = listen_dhcp_client(iface).await?;

    let mac_address = network_interface::NetworkInterface::show()
        .map_err(|x| io::Error::new(io::ErrorKind::Other, format!("list ifaces: {:?}", iface)))?
        .into_iter()
        .find(|x| x.name == iface)
        .ok_or(io::Error::new(
            io::ErrorKind::Other,
            format!("can not find interface: {}", iface),
        ))?
        .mac_addr
        .ok_or(io::Error::new(
            io::ErrorKind::Other,
            format!("no MAC address on interface: {}", iface),
        ))?;

    let mut msg = dhcproto::v4::Message::default();
    msg.set_flags(dhcproto::v4::Flags::default().set_broadcast())
        .set_chaddr(&mac_address.as_str().as_bytes())
        .opts_mut()
        .insert(dhcproto::v4::DhcpOption::MessageType(
            dhcproto::v4::MessageType::Discover,
        ));

    msg.opts_mut()
        .insert(dhcproto::v4::DhcpOption::ParameterRequestList(vec![
            dhcproto::v4::OptionCode::SubnetMask,
            dhcproto::v4::OptionCode::Router,
            dhcproto::v4::OptionCode::DomainNameServer,
            dhcproto::v4::OptionCode::DomainName,
        ]));

    socket
        .send_to(&msg.to_vec().expect("must encode"), "255.255.255.255:67")
        .await?;

    async fn receive_offer(socket: UdpSocket, xid: u32) -> io::Result<Vec<Ipv4Addr>> {
        let mut buf = vec![0u8; 576];
        loop {
            let (n_read, _) = socket.recv_from(&mut buf).await?;

            if let Ok(reply) = dhcproto::v4::Message::from_bytes(&buf[..n_read]) {
                if let Some(op) = reply.opts().get(dhcproto::v4::OptionCode::MessageType) {
                    match op {
                        dhcproto::v4::DhcpOption::MessageType(msg_type) => {
                            if msg_type == &dhcproto::v4::MessageType::Offer {
                                if reply.xid() == xid {
                                    if let Some(op) =
                                        reply.opts().get(dhcproto::v4::OptionCode::DomainNameServer)
                                    {
                                        match op {
                                            dhcproto::v4::DhcpOption::DomainNameServer(dns) => {
                                                return Ok(dns.to_owned());
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    tokio::select! {
        result = receive_offer(socket, msg.xid()) => {
            match result {
                Ok(dns) => Ok(dns),
                Err(err) => Err(err),
            }
        },
        _ = tokio::time::sleep(Duration::from_secs(10)) => Err(io::Error::new(io::ErrorKind::Other, "dhcp timeout")),
    }
}
