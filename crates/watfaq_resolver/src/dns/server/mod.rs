use std::sync::Arc;

use hickory_proto::op::Message;

use tracing::error;
use watfaq_dns::DNSListenAddr;

mod handler;
pub use handler::exchange_with_resolver;

use crate::Resolver;

static DEFAULT_DNS_SERVER_TTL: u32 = 60;

pub struct DnsMessageExchanger {
    resolver: Arc<Resolver>,
}

impl DnsMessageExchanger {
    async fn exchange(
        &self,
        message: &Message,
    ) -> Result<Message, watfaq_dns::DNSError> {
        exchange_with_resolver(&self.resolver, message, true).await
    }
}

// TODO tokio::JoinSet
// pub async fn get_dns_listener(
//     listen: DNSListenAddr,
//     resolver: Resolver,
//     cwd: &std::path::Path,
// ) -> Option<Runner> {
//     let h = DnsMessageExchanger { resolver };
//     let r = watfaq_dns::get_dns_listener(listen, h, cwd).await;
//     match r {
//         Some(r) => Some(Box::pin(async move {
//             match r.await {
//                 Ok(()) => Ok(()),
//                 Err(err) => {
//                     error!("dns listener error: {}", err);
//                     Err(err.into())
//                 }
//             }
//         })),
//         _ => None,
//     }
// }
