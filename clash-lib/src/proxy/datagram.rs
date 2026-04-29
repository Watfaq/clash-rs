use crate::session::SocksAddr;
use std::fmt::{Debug, Display, Formatter};

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    /// Logical destination for this packet. For fake-IP setups the dispatcher
    /// rewrites this to the resolved domain before forwarding, so proxy
    /// outbounds always see the intended domain rather than a fake-IP.
    pub dst_addr: SocksAddr,
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
            inbound_user: None,
        }
    }
}
