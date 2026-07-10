//! Hysteria2 protocol support: outbound client and inbound server, plus the
//! shared QUIC framing/codec, congestion control, and UDP fragmentation used by
//! both sides.

mod codec;
mod congestion;
mod datagram;
mod salamander;
mod stream;
mod udp_hop;

pub mod inbound;
pub mod outbound;

// Re-export the outbound surface at the module root for existing call sites
// (e.g. `hysteria2::Handler`, `hysteria2::HystOption`).
pub use outbound::{Handler, HystOption, Obfs, SalamanderObfs};
