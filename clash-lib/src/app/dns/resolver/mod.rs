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
    app::profile::ThreadSafeCacheFile, dns::filters::PendingMmdb, 
    proxy::utils::OutboundHandlerRegistry,
};

pub async fn new(
    cfg: Config,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<PendingMmdb>,
    outbounds: OutboundHandlerRegistry,
) -> crate::Result<ThreadSafeDNSResolver> {
    if cfg.enable {
        match store {
            Some(store) => {
                Ok(Arc::new(EnhancedResolver::new(cfg, store, mmdb, outbounds).await))
            }
            _ => Err(crate::Error::InvalidConfig("enhanced resolver requires cache store".into())),
        }
    } else {
        Ok(Arc::new(
            SystemResolver::new(cfg.ipv6).map_err(|e| crate::Error::DNSError(e.to_string()))?,
        ))
    }
}
