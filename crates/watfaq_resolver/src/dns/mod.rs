pub mod config;
pub mod dhcp;
pub mod dns_client;
mod fakeip;
mod filters;
mod helper;
pub mod resolver;
mod runtime;
mod server;

pub use config::DnsConfig;
pub use server::exchange_with_resolver;