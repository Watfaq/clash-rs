use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

#[cfg(test)]
pub mod test_utils;

mod platform;

pub mod provider_helper;
mod proxy_connector;
mod socket_helpers;

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
pub use proxy_connector::*;

use serde::{Deserialize, Serialize};
pub use socket_helpers::*;
use tracing::trace;
