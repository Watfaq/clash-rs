use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use serde::Serialize;

use crate::{Network, TargetAddr};

#[derive(Serialize, Clone)]
pub struct Session {
    /// The type of the inbound connection.
    pub typ: Type,
    /// The network type, representing either TCP or UDP.
    pub network: Network,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: TargetAddr,
    /// The locally resolved IP address of the destination domain.
    /// TODO resolve depends on Conext stack prefer
    pub resolved_ip: Option<IpAddr>,

    /// The ASN of the destination IP address. Only for display.
    pub asn: Option<String>,
}

impl Session {
    pub fn as_map(
        &self,
    ) -> HashMap<String, Box<dyn erased_serde::Serialize + Send + Sync>> {
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
            network: Network::TCP,
            typ: Type::Http,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            destination: TargetAddr::any_ipv4(),
            resolved_ip: None,
            asn: None,
        }
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] {} -> {}",
            self.network, self.source, self.destination,
        )
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("network", &self.network)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("asn", &self.asn)
            .finish()
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Type {
    Http,
    HttpConnect,
    Socks5,
    Tun,
    Tproxy,
    Tunnel,
    Ignore,
}
