use ipnet::IpNet;
use tracing::warn;

use crate::proxy::utils::OutboundInterface;

pub fn add_route(_: &OutboundInterface, _: &IpNet) -> std::io::Result<()> {
    warn!("add_route is not implemented on {}", std::env::consts::OS);
    Ok(())
}
