use async_trait::async_trait;
use erased_serde::Serialize;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    io,
    sync::Arc,
};

pub mod fetcher;
pub mod file_vehicle;
pub mod http_vehicle;
pub mod proxy_provider;
pub mod rule_provider;

#[cfg(test)]
use mockall::automock;

#[derive(Deserialize, PartialEq, Clone, Copy, Debug)]
pub enum ProviderVehicleType {
    File,
    Http,
    Compatible,
}

impl Display for ProviderVehicleType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderVehicleType::File => write!(f, "File"),
            ProviderVehicleType::Http => write!(f, "HTTP"),
            ProviderVehicleType::Compatible => write!(f, "Compatible"),
        }
    }
}

pub type ThreadSafeProviderVehicle = Arc<dyn ProviderVehicle + Send + Sync>;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait ProviderVehicle {
    async fn read(&self) -> io::Result<Vec<u8>>;
    fn path(&self) -> &str;
    fn typ(&self) -> ProviderVehicleType;
}

pub enum ProviderType {
    Proxy,
    Rule,
}
impl Display for ProviderType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::Proxy => write!(f, "Proxy"),
            ProviderType::Rule => write!(f, "Rule"),
        }
    }
}

/// either Proxy or Rule provider
#[async_trait]
pub trait Provider {
    fn name(&self) -> &str;
    fn vehicle_type(&self) -> ProviderVehicleType;
    fn typ(&self) -> ProviderType;
    async fn initialize(&self) -> io::Result<()>;
    async fn update(&self) -> io::Result<()>;

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>>;
}
