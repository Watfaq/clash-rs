use async_trait::async_trait;
use std::fmt::{Display, Formatter};
use std::io;

mod file_vehicle;
mod http_vehicle;
pub mod proxy_provider;
pub mod rule_provider;

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

#[async_trait]
trait ProviderVehicle {
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
pub trait Provider {
    fn name(&self) -> &str;
    fn vehicle_type(&self) -> ProviderVehicleType;
    fn typ(&self) -> ProviderType;
    fn initialize(&self) -> io::Error;
    fn update(&self) -> io::Error;
}
