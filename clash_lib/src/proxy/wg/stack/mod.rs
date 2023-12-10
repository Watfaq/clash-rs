pub mod tcp;
pub mod udp;

use async_trait::async_trait;
use std::fmt::{Display, Formatter};

use super::{device::VirtualIpDevice, events::PortProtocol};

#[async_trait]
pub trait VirtualInterfacePoll {
    /// Initializes the virtual interface and processes incoming data to be dispatched
    /// to the WireGuard tunnel and to the real client.
    async fn poll_loop(mut self, device: VirtualIpDevice) -> std::io::Result<()>;
}

/// Virtual port.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct VirtualPort(u16, PortProtocol);

impl VirtualPort {
    /// Create a new `VirtualPort` instance, with the given port number and associated protocol.
    pub fn new(port: u16, proto: PortProtocol) -> Self {
        VirtualPort(port, proto)
    }

    /// The port number
    pub fn num(&self) -> u16 {
        self.0
    }

    /// The protocol of this port.
    pub fn proto(&self) -> PortProtocol {
        self.1
    }
}

impl From<VirtualPort> for u16 {
    fn from(port: VirtualPort) -> Self {
        port.num()
    }
}

impl From<&VirtualPort> for u16 {
    fn from(port: &VirtualPort) -> Self {
        port.num()
    }
}

impl From<VirtualPort> for PortProtocol {
    fn from(port: VirtualPort) -> Self {
        port.proto()
    }
}

impl From<&VirtualPort> for PortProtocol {
    fn from(port: &VirtualPort) -> Self {
        port.proto()
    }
}

impl Display for VirtualPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}:{}]", self.num(), self.proto())
    }
}
