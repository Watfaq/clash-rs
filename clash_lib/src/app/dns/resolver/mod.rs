mod enhanced;

#[cfg(target_os = "linux")]
#[path = "system_linux.rs"]
mod system;
#[cfg(not(target_os = "linux"))]
#[path = "system_non_linux.rs"]
mod system;

use std::sync::Arc;

pub use enhanced::EnhancedResolver;
pub use system::SystemResolver;

use crate::{app::profile::ThreadSafeCacheFile, common::mmdb::Mmdb};

use super::{Config, ThreadSafeDNSResolver};

pub async fn new(
    cfg: &Config,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<Arc<Mmdb>>,
) -> ThreadSafeDNSResolver {
    if cfg.enable {
        match (store, mmdb) {
            (Some(store), Some(mmdb)) => {
                EnhancedResolver::new(cfg, store, mmdb).await
            }
            _ => panic!("enhanced resolver requires cache store and mmdb"),
        }
    } else {
        Arc::new(
            SystemResolver::new(cfg.ipv6).expect("failed to create system resolver"),
        )
    }
}
