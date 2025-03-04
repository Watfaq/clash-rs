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

use crate::{app::profile::ThreadSafeCacheFile, common::mmdb::Mmdb};

use super::{Config, ThreadSafeDNSResolver};

pub async fn new(cfg: Config, mmdb: Option<Arc<Mmdb>>) -> ThreadSafeDNSResolver {
    if cfg.enable {
        match (store, mmdb) {
            (Some(store), Some(mmdb)) => {
                Arc::new(EnhancedResolver::new(cfg, store, mmdb).await)
            }
            _ => panic!("enhanced resolver requires cache store and mmdb"),
        }
    } else {
        Arc::new(
            SystemResolver::new(cfg.ipv6).expect("failed to create system resolver"),
        )
    }
}
