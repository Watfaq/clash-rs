use std::fmt::{Debug, Display, Formatter};

use super::TargetAddr;

type SourceAddr = TargetAddr;
type DestinationAddr = TargetAddr;

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SourceAddr,
    pub dst_addr: DestinationAddr,
}

impl Default for UdpPacket {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            src_addr: TargetAddr::any_ipv4(),
            dst_addr: TargetAddr::any_ipv4(),
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
    pub fn new(
        data: Vec<u8>,
        src_addr: SourceAddr,
        dst_addr: DestinationAddr,
    ) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
        }
    }
}
