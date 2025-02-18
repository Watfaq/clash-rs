use crate::{
    dns::{
        dns_client::DNSNetMode, helper::make_clients, Client, EnhancedResolver,
        ThreadSafeDNSClient,
    },
    proxy::utils::new_udp_socket,
};
use async_trait::async_trait;
use dhcproto::{Decodable, Encodable};
use futures::FutureExt;
use network_interface::{Addr, NetworkInterfaceConfig};
use std::{
    env,
    fmt::{Debug, Formatter},
    io,
    net::Ipv4Addr,
    ops::Add,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::Mutex, task::yield_now};

use hickory_proto::op::Message;
use tracing::debug;

use super::config::NameServer;

const IFACE_TTL: Duration = Duration::from_secs(20);
const DHCP_TTL: Duration = Duration::from_secs(3600);
const DHCP_TIMEOUT: Duration = Duration::from_secs(60);

struct Inner {
    clients: Vec<ThreadSafeDNSClient>,
    iface_expires_at: std::time::Instant,
    dns_expires_at: std::time::Instant,
    iface_addr: ipnet::IpNet,
}

pub struct DhcpClient {
    iface: String,

    inner: Mutex<Inner>,
}

impl Debug for DhcpClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhcpClient")
            .field("iface", &self.iface)
            .finish()
    }
}

#[async_trait]
impl Client for DhcpClient {
    fn id(&self) -> String {
        format!("dhcp#{}", self.iface)
    }

    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
        let clients = self.resolve().await?;
        let mut dbg_str = vec![];
        for c in &clients {
            dbg_str.push(format!("{:?}", c));
        }
        debug!("using clients: {:?}", dbg_str);
        tokio::time::timeout(
            DHCP_TIMEOUT,
            EnhancedResolver::batch_exchange(&clients, msg),
        )
        .await?
    }
}

impl DhcpClient {
    pub async fn new(iface: &str) -> Self {
        Self {
            iface: iface.to_owned(),
            inner: Mutex::new(Inner {
                clients: vec![],
                iface_expires_at: Instant::now(),
                dns_expires_at: Instant::now(),
                iface_addr: ipnet::IpNet::default(),
            }),
        }
    }

    async fn resolve(&self) -> io::Result<Vec<ThreadSafeDNSClient>> {
        let expired = self.update_if_lease_expired().await?;
        if expired {
            let dns = probe_dns_server(&self.iface).await?;
            let mut inner = self.inner.lock().await;

            inner.clients = make_clients(
                dns.into_iter()
                    .map(|s| NameServer {
                        net: DNSNetMode::Udp,
                        address: format!("{}:53", s),
                        interface: None,
                    })
                    .collect(),
                None,
            )
            .await;
        }

        Ok(self.inner.lock().await.clients.clone())
    }

    /// Check if interface updated or DHCP changed
    /// and update if necessary
    async fn update_if_lease_expired(&self) -> io::Result<bool> {
        let mut inner = self.inner.lock().await;
        if inner.clients.is_empty() {
            return Ok(true);
        }

        if Instant::now() < inner.iface_expires_at {
            return Ok(false);
        }

        inner.iface_expires_at = Instant::now().add(IFACE_TTL);

        let iface = network_interface::NetworkInterface::show()
            .map_err(|x| {
                io::Error::new(io::ErrorKind::Other, format!("list ifaces: {:?}", x))
            })?
            .into_iter()
            .find(|x| {
                x.name == self.iface
                    && x.addr.first().map(|x| x.ip().is_ipv4()).unwrap_or(false)
            })
            .ok_or(io::Error::new(
                io::ErrorKind::Other,
                format!("can not find interface: {}", self.iface),
            ))?;

        // TODO: this API changed, need to check if .first() is expected. same
        // to L103
        let addr = iface.addr.first().ok_or(io::Error::new(
            io::ErrorKind::Other,
            format!("no address on interface: {}", self.iface),
        ))?;

        match addr {
            Addr::V4(v4) => {
                if Instant::now() < inner.dns_expires_at
                    && inner.iface_addr.addr() == v4.ip
                    && inner.iface_addr.netmask()
                        == v4.netmask.ok_or(io::Error::new(
                            io::ErrorKind::Other,
                            format!("no netmask on iface: {}", self.iface),
                        ))?
                {
                    Ok(false)
                } else {
                    inner.dns_expires_at = Instant::now().add(DHCP_TTL);
                    inner.iface_addr = ipnet::IpNet::new(
                        v4.ip.into(),
                        u32::from(v4.netmask.ok_or(io::Error::new(
                            io::ErrorKind::Other,
                            "no netmask",
                        ))?)
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
        Some(listen_addr.parse().expect("must parse")),
        Some(iface.into()),
        #[cfg(target_os = "linux")]
        None,
    )
    .await
}

async fn probe_dns_server(iface: &str) -> io::Result<Vec<Ipv4Addr>> {
    debug!("probing NS servers from DHCP");
    let socket = listen_dhcp_client(iface).await?;

    let mac_address: Vec<u8> = network_interface::NetworkInterface::show()
        .map_err(|_x| {
            io::Error::new(io::ErrorKind::Other, format!("list ifaces: {:?}", iface))
        })?
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
        .split(':')
        .map(|x| {
            u8::from_str_radix(x, 16).map_err(|_x| {
                io::Error::new(io::ErrorKind::Other, "malformed MAC addr")
            })
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
                if let Ok(reply) = dhcproto::v4::Message::from_bytes(&buf[..n_read])
                {
                    if let Some(op) =
                        reply.opts().get(dhcproto::v4::OptionCode::MessageType)
                    {
                        match op {
                            dhcproto::v4::DhcpOption::MessageType(msg_type) => {
                                if msg_type == &dhcproto::v4::MessageType::Offer {
                                    if reply.xid() == xid {
                                        if let Some(op) = reply.opts().get(
                                            dhcproto::v4::OptionCode::DomainNameServer,
                                        ) {
                                            match op {
                                                dhcproto::v4::DhcpOption::DomainNameServer(dns) => {
                                                    debug!(
                                                        "got NS servers {:?} from DHCP",
                                                        dns
                                                    );
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
            value = get_response => tx.send(value).map_err(|x| debug!("send error: {:?}", x)).unwrap_or_default(),
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
            Err(io::Error::new(io::ErrorKind::Other, "dhcp timeout"))
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
