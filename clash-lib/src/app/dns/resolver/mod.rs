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

use super::{Config, ThreadSafeDNSResolver};
use crate::{
    app::profile::ThreadSafeCacheFile, common::mmdb::MmdbLookup, print_and_exit,
};

pub async fn new(
    cfg: Config,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<MmdbLookup>,
) -> ThreadSafeDNSResolver {
    if cfg.enable {
        match store {
            Some(store) => Arc::new(EnhancedResolver::new(cfg, store, mmdb).await),
            _ => print_and_exit!("enhanced resolver requires cache store"),
        }
    } else {
        Arc::new(
            SystemResolver::new(cfg.ipv6).expect("failed to create system resolver"),
        )
    }
}
