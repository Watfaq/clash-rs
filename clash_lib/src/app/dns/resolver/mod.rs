mod enhanced;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "system_linux.rs"]
mod system;
#[cfg(all(not(target_os = "linux"), not(target_os = "android")))]
#[path = "system_non_linux.rs"]
mod system;

use std::sync::Arc;

pub use enhanced::EnhancedResolver;
pub use system::SystemResolver;

use crate::{app::profile::ThreadSafeCacheFile, common::mmdb::Mmdb};

use super::{Config, ThreadSafeDNSResolver};

pub async fn new(
    cfg: Config,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<Arc<Mmdb>>,
) -> ThreadSafeDNSResolver {
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
