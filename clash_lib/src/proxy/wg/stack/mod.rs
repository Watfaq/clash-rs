pub mod tcp;
pub mod udp;

use async_trait::async_trait;

use super::device::VirtualIpDevice;

#[async_trait]
pub trait VirtualInterfacePoll {
    /// Initializes the virtual interface and processes incoming data to be dispatched
    /// to the WireGuard tunnel and to the real client.
    async fn poll_loop(mut self, device: VirtualIpDevice) -> std::io::Result<()>;
}
