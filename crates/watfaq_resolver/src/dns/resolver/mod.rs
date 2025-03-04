mod dummy;
mod enhanced;

#[cfg(all(target_feature = "crt-static", target_env = "gnu"))]
#[path = "system_static_crt.rs"]
mod system;

#[cfg(not(all(target_feature = "crt-static", target_env = "gnu")))]
#[path = "system.rs"]
mod system;

use std::sync::Arc;

pub use enhanced::EnhancedResolver;
pub use system::SystemResolver;
pub use dummy::DummyResolver;

use watfaq_utils::Mmdb;
use watfaq_error::Result;

use crate::Resolver;

use super::Config;

pub async fn new(cfg: Config, mmdb: Option<Arc<Mmdb>>) -> Result<Resolver> {
    let resolver = if cfg.enable {
        match mmdb {
            Some(mmdb) => EnhancedResolver::new(cfg, mmdb).await?.into(),
            _ => panic!("enhanced resolver requires cache store and mmdb"),
        }
    } else {
        SystemResolver::new(cfg.ipv6)?.into()
    };
    Ok(resolver)
}
