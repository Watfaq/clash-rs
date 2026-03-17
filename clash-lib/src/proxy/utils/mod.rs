#[cfg(test)]
pub mod test_utils;

mod platform;

pub mod provider_helper;
mod proxy_connector;
mod shared_handler;
mod socket_helpers;

pub use proxy_connector::*;
pub use shared_handler::{
    OutboundHandlerRegistry, SharedOutboundHandler, direct_only_registry,
};
pub use socket_helpers::*;
