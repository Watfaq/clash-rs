pub mod client;

pub use client::*;

pub const DEFAULT_USER_AGENT: &str = concat!("clash-rs/", env!("CARGO_PKG_VERSION"));
