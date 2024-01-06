use async_trait::async_trait;
use std::fs;

use super::{ProviderVehicle, ProviderVehicleType};

pub struct Vehicle {
    path: String,
}

impl Vehicle {
    pub fn new(path: &str) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl ProviderVehicle for Vehicle {
    async fn read(&self) -> std::io::Result<Vec<u8>> {
        fs::read(&self.path)
    }

    fn path(&self) -> &str {
        self.path.as_str()
    }

    fn typ(&self) -> ProviderVehicleType {
        ProviderVehicleType::File
    }
}
