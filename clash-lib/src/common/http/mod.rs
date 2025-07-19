pub mod client;
pub mod hyper;

pub use client::*;
pub use hyper::HyperResponseBody;

pub const DEFAULT_USER_AGENT: &str = concat!("clash-rs/", env!("CARGO_PKG_VERSION"));
