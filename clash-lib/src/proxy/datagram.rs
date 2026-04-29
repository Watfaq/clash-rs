use crate::session::SocksAddr;
use std::fmt::{Debug, Display, Formatter};

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    /// Original inbound destination (fake-IP or real IP from the client).
    /// This field is **never overwritten** after inbound parsing; it always
    /// reflects what the client sent.
    pub dst_addr: SocksAddr,
    /// Domain resolved from `dst_addr` via reverse-lookup (fake-IP → domain,
    /// or cache hit). Always a `SocksAddr::Domain` when set. Set by the
    /// dispatcher; `None` when the destination is a plain IP with no
    /// associated domain. Used for rule matching and as the address written
    /// into proxy-protocol headers instead of the fake-IP.
    ///
    /// **Invariant**: if `dst_addr` is a fake-IP, this field **must** be
    /// `Some`; sending a fake-IP without a domain is a dispatcher bug.
    pub dst_domain: Option<SocksAddr>,
    /// Authenticated user name from SS2022 EIH, propagated to the dispatcher
    /// session for per-user traffic attribution. `None` for all other
    /// protocols.
    pub inbound_user: Option<String>,
}

impl Default for UdpPacket {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::any_ipv4(),
            dst_domain: None,
            inbound_user: None,
        }
    }
}

impl Debug for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .finish()
    }
}

impl Display for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP Packet from {} to {} with {} bytes",
            self.src_addr,
            self.dst_addr,
            self.data.len()
        )
    }
}

impl UdpPacket {
    pub fn new(data: Vec<u8>, src_addr: SocksAddr, dst_addr: SocksAddr) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
            dst_domain: None,
            inbound_user: None,
        }
    }

    /// Returns the logical destination for outbound use: the resolved domain
    /// if one was set, otherwise `dst_addr`.
    ///
    /// Proxy-protocol headers should use this so that the remote proxy server
    /// sees the intended domain name rather than a fake-IP.
    pub fn logical_dst(&self) -> SocksAddr {
        self.dst_domain
            .clone()
            .unwrap_or_else(|| self.dst_addr.clone())
    }
}
