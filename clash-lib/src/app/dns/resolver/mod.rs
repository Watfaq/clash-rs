mod enhanced;

#[cfg(all(target_feature = "crt-static", target_env = "gnu"))]
#[path = "system_static_crt.rs"]
mod system;

#[cfg(not(all(target_feature = "crt-static", target_env = "gnu")))]
#[path = "system.rs"]
mod system;

use std::{collections::HashMap, sync::Arc};

pub use enhanced::EnhancedResolver;
pub use system::SystemResolver;

use super::{Config, ThreadSafeDNSResolver};
use crate::{
    app::profile::ThreadSafeCacheFile, common::mmdb::MmdbLookup, print_and_exit,
    proxy::OutboundHandler,
};

pub async fn new(
    cfg: Config,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<MmdbLookup>,
    outbounds: HashMap<String, Arc<dyn OutboundHandler>>,
    proxy_server_domains: Vec<String>,
) -> ThreadSafeDNSResolver {
    if cfg.enable {
        match store {
            Some(store) => Arc::new(
                EnhancedResolver::new(
                    cfg,
                    store,
                    mmdb,
                    outbounds,
                    proxy_server_domains,
                )
                .await,
            ),
            _ => print_and_exit!("enhanced resolver requires cache store"),
        }
    } else {
        Arc::new(
            SystemResolver::new(cfg.ipv6).expect("failed to create system resolver"),
        )
    }
}
