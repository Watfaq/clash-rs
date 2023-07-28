use async_trait::async_trait;
use std::fmt::{Display, Formatter};
use std::io;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod fether;
mod file_vehicle;
mod http_vehicle;
pub mod proxy_provider;
pub mod rule_provider;

#[cfg(test)]
use mockall::automock;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ProviderVehicleType {
    File,
    HTTP,
    Compatible,
}

impl Display for ProviderVehicleType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderVehicleType::File => write!(f, "File"),
            ProviderVehicleType::HTTP => write!(f, "HTTP"),
            ProviderVehicleType::Compatible => write!(f, "Compatible"),
        }
    }
}

pub type ThreadSafeProviderVehicle = Arc<Mutex<dyn ProviderVehicle + Send + Sync>>;

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
    async fn name(&self) -> &str;
    async fn vehicle_type(&self) -> ProviderVehicleType;
    async fn typ(&self) -> ProviderType;
    async fn initialize(&mut self) -> io::Result<()>;
    async fn update(&self) -> io::Result<()>;
}
