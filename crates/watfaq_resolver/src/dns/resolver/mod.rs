mod dummy;
mod enhanced;

#[cfg(all(target_feature = "crt-static", target_env = "gnu"))]
#[path = "system_static_crt.rs"]
mod system;

#[cfg(not(all(target_feature = "crt-static", target_env = "gnu")))]
#[path = "system.rs"]
mod system;

use std::{sync::Arc, time::Duration};

pub use dummy::DummyResolver;
pub use enhanced::EnhancedResolver;
use futures::FutureExt;
use hickory_proto::op as hickory;
use rustls::client;
pub use system::SystemResolver;

use tracing::error;
use watfaq_error::{Result, anyhow};
use watfaq_state::Context;
use watfaq_utils::Mmdb;

use crate::{AbstractDnsClient, DnsClient, Resolver};

use super::DnsConfig;

pub async fn new(
    ctx: Arc<Context>,
    cfg: DnsConfig,
    mmdb: Option<Arc<Mmdb>>,
) -> Result<Resolver> {
    let resolver = if cfg.enable {
        match mmdb {
            Some(mmdb) => EnhancedResolver::new(ctx, cfg, mmdb).await?.into(),
            _ => panic!("enhanced resolver requires cache store and mmdb"),
        }
    } else {
        SystemResolver::new(cfg.ipv6)?.into()
    };
    Ok(resolver)
}
// TODO move this to a better place
pub async fn batch_exchange(
    clients: &Vec<DnsClient>,
    message: &hickory::Message,
) -> Result<hickory::Message> {
    // TODO tokio JoinSet
    // tokio::task::join_set::LocalSet
    let mut set = tokio::task::JoinSet::new();

    for client in clients {
        let client = client.to_owned();
        let msg = message.clone();
        set.spawn_local(async move {
            client.exchange(&msg).await.inspect_err(|x| {
                error!(
                    "DNS client {} resolve error: {}",
                    client.id(),
                    x.to_string()
                )
            })
        });
    }

    // TODO remove hardcode
    let timeout = tokio::time::sleep(Duration::from_secs(10));

    todo!()
}
