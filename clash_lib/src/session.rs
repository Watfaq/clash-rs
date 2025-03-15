use std::{
    collections::HashMap,
    fmt::{Debug, Display, Formatter},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use serde::Serialize;

use erased_serde::Serialize as ESerialize;

use crate::app::net::Interface;

pub use crate::modules::types::TargetAddr;

pub struct SocksAddrType;

impl SocksAddrType {
    pub const DOMAIN: u8 = 0x3;
    pub const V4: u8 = 0x1;
    pub const V6: u8 = 0x4;
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Type {
    Http,
    HttpConnect,
    Socks5,
    Tun,
    #[cfg(target_os = "linux")]
    Tproxy,
    Tunnel,
    Ignore,
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Network::Tcp => "TCP",
            Network::Udp => "UDP",
        })
    }
}

#[derive(Serialize)]
pub struct Session {
    /// The network type, representing either TCP or UDP.
    pub network: Network,
    /// The type of the inbound connection.
    pub typ: Type,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: TargetAddr,
    /// The locally resolved IP address of the destination domain.
    pub resolved_ip: Option<IpAddr>,
    /// The packet mark SO_MARK
    pub so_mark: Option<u32>,
    /// The bind interface
    pub iface: Option<Interface>,
    /// The ASN of the destination IP address. Only for display.
    pub asn: Option<String>,
}

impl Session {
    pub fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send + Sync>> {
        let mut rv = HashMap::new();
        rv.insert("network".to_string(), Box::new(self.network) as _);
        rv.insert("type".to_string(), Box::new(self.typ) as _);
        rv.insert("sourceIP".to_string(), Box::new(self.source.ip()) as _);
        rv.insert("sourcePort".to_string(), Box::new(self.source.port()) as _);
        rv.insert("destinationIP".to_string(), {
            let ip = self.resolved_ip.or(self.destination.ip());
            let asn = self.asn.clone();

            let rv = match (ip, asn) {
                (Some(ip), Some(asn)) => format!("{}({})", ip, asn),
                (Some(ip), None) => ip.to_string(),
                (None, _) => "".to_string(),
            };
            Box::new(rv) as _
        });
        rv.insert(
            "destinationPort".to_string(),
            Box::new(self.destination.port()) as _,
        );
        rv.insert("host".to_string(), Box::new(self.destination.host()) as _);
        rv.insert("asn".to_string(), Box::new(self.asn.clone()) as _);
        rv
    }
}

impl Default for Session {
    fn default() -> Self {
        Self {
            network: Network::Tcp,
            typ: Type::Http,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            destination: TargetAddr::any_ipv4(),
            resolved_ip: None,
            so_mark: None,
            iface: None,
            asn: None,
        }
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} -> {}",
            self.network, self.source, self.destination,
        )
    }
}

impl Debug for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("network", &self.network)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("packet_mark", &self.so_mark)
            .field("iface", &self.iface)
            .field("asn", &self.asn)
            .finish()
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            network: self.network,
            typ: self.typ,
            source: self.source,
            destination: self.destination.clone(),
            resolved_ip: self.resolved_ip,
            so_mark: self.so_mark,
            iface: self.iface.as_ref().cloned(),
            asn: self.asn.clone(),
        }
    }
}
