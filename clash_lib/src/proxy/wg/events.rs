/// Layer 7 protocols for ports.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PortProtocol {
    /// TCP
    Tcp,
    /// UDP
    Udp,
}
