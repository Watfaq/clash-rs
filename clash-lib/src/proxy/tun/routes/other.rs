use ipnet::IpNet;
use tracing::warn;

use crate::{app::net::OutboundInterface, config::internal::config::TunConfig};

#[allow(dead_code)]
pub fn add_route(_: &OutboundInterface, _: &IpNet) -> std::io::Result<()> {
    warn!("add_route is not implemented on {}", std::env::consts::OS);
    Ok(())
}

pub fn maybe_routes_clean_up(_: &TunConfig) -> std::io::Result<()> {
    warn!(
        "maybe_routes_clean_up is not implemented on {}",
        std::env::consts::OS
    );
    Ok(())
}
