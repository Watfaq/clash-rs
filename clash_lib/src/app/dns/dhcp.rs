use crate::dns::dns_client::DNSNetMode;
use crate::dns::helper::make_clients;
use crate::dns::{Client, NameServer, Resolver, ThreadSafeDNSClient};
use crate::proxy::utils::{new_udp_socket, Interface};
use async_trait::async_trait;
use dhcproto::{Decodable, Encodable};
use futures::FutureExt;
use network_interface::{Addr, NetworkInterfaceConfig};
use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{env, io};
use tokio::net::UdpSocket;
use tokio::task::yield_now;

use tracing::{debug, warn};
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

impl Debug for DhcpClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhcpClient")
            .field("iface", &self.iface)
            .field("iface_addr", &self.iface_addr)
            .field("iface_expires_at", &self.iface_expires_at)
            .field("clients", &self.clients)
            .field("dns_expires_at", &self.dns_expires_at)
            .finish()
    }
}

#[async_trait]
impl Client for DhcpClient {
    async fn exchange(&mut self, msg: &Message) -> anyhow::Result<Message> {
        let clients = self.resolve().await?;
        debug!("using clients: {:?}", clients);
        tokio::time::timeout(DHCP_TIMEOUT, Resolver::batch_exchange(clients, msg)).await?
    }
}

impl DhcpClient {
    pub async fn new(iface: &str) -> Self {
        Self {
            iface: iface.to_owned(),
            iface_addr: ipnet::IpNet::default(),
            clients: vec![],
            iface_expires_at: Instant::now(),
            dns_expires_at: Instant::now(),
        }
    }

    async fn resolve(&mut self) -> io::Result<&Vec<ThreadSafeDNSClient>> {
        let expired = self.update_if_lease_expired()?;
        if expired {
            let dns = probe_dns_server(&self.iface).await?;
            self.clients = make_clients(
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
    fn update_if_lease_expired(&mut self) -> io::Result<bool> {
        if self.clients.is_empty() {
            return Ok(true);
        }

        if Instant::now() < self.iface_expires_at {
            return Ok(false);
        }

        self.iface_expires_at = Instant::now().add(IFACE_TTL);

        let iface = network_interface::NetworkInterface::show()
            .map_err(|x| io::Error::new(io::ErrorKind::Other, format!("list ifaces: {:?}", x)))?
            .into_iter()
            .find(|x| {
                x.name == self.iface && x.addr.first().map(|x| x.ip().is_ipv4()).unwrap_or(false)
            })
            .ok_or(io::Error::new(
                io::ErrorKind::Other,
                format!("can not find interface: {}", self.iface),
            ))?;

        // TODO: this API changed, need to check if .first() is expected. same to L103
        let addr = iface.addr.first().ok_or(io::Error::new(
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
                    .map_err(|_x| {
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
        "linux" => "255.255.255.255:68",
        _ => "0.0.0.0:68",
    };

    new_udp_socket(
        Some(&listen_addr.parse().expect("must parse")),
        Some(&Interface::Name(iface.to_string())),
    )
    .await
}

async fn probe_dns_server(iface: &str) -> io::Result<Vec<Ipv4Addr>> {
    debug!("probing NS servers from DHCP");
    let socket = listen_dhcp_client(iface).await?;

    let mac_address: Vec<u8> = network_interface::NetworkInterface::show()
        .map_err(|_x| io::Error::new(io::ErrorKind::Other, format!("list ifaces: {:?}", iface)))?
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
        ))?
        .split(":")
        .map(|x| {
            u8::from_str_radix(x, 16)
                .map_err(|_x| io::Error::new(io::ErrorKind::Other, "malformed MAC addr"))
        })
        .collect::<io::Result<Vec<u8>>>()?;

    let mut msg = dhcproto::v4::Message::default();
    msg.set_flags(dhcproto::v4::Flags::default().set_broadcast())
        .set_chaddr(mac_address.as_slice())
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

    let (mut tx, rx) = tokio::sync::oneshot::channel::<Vec<Ipv4Addr>>();

    let mut rx = rx.fuse();

    let r = Arc::new(socket);
    let s = r.clone();

    let xid = msg.xid();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 576];

        let get_response = async move {
            loop {
                let (n_read, _) = r
                    .recv_from(&mut buf)
                    .await
                    .expect("failed to receive DHCP offer");

                // fucking deep if-else hell
                if let Ok(reply) = dhcproto::v4::Message::from_bytes(&buf[..n_read]) {
                    if let Some(op) = reply.opts().get(dhcproto::v4::OptionCode::MessageType) {
                        match op {
                            dhcproto::v4::DhcpOption::MessageType(msg_type) => {
                                if msg_type == &dhcproto::v4::MessageType::Offer {
                                    if reply.xid() == xid {
                                        if let Some(op) = reply
                                            .opts()
                                            .get(dhcproto::v4::OptionCode::DomainNameServer)
                                        {
                                            match op {
                                                dhcproto::v4::DhcpOption::DomainNameServer(dns) => {
                                                    debug!("got NS servers {:?} from DHCP", dns);
                                                    return dns.clone();
                                                }
                                                _ => yield_now().await,
                                            }
                                        }
                                    }
                                    yield_now().await
                                }
                            }
                            _ => yield_now().await,
                        }
                    }
                }
            }
        };

        tokio::select! {
            _ = tx.closed() => {debug!("future cancelled, likely other clients won")},
            value = get_response => tx.send(value).map_err(|x| warn!("send error: {:?}", x)).unwrap_or_default(),
        }
    });

    s.send_to(&msg.to_vec().expect("must encode"), "255.255.255.255:67")
        .await?;

    tokio::select! {
        result = &mut rx => {
            result.map_err(|_x| io::Error::new(io::ErrorKind::Other, "channel error"))
        },

        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            debug!("DHCP timeout after 10 secs");
            return Err(io::Error::new(io::ErrorKind::Other, "dhcp timeout"));
        }
    }
}

#[cfg(test)]
mod test {
    use crate::dns::dhcp::probe_dns_server;

    #[tokio::test]
    #[ignore]
    async fn test_probe_ns() {
        let ns = probe_dns_server("en0").await.expect("must prob");
        assert!(!ns.is_empty());
    }
}
