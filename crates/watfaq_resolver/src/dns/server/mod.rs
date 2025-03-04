use hickory_proto::op::Message;

use tracing::error;
use watfaq_dns::DNSListenAddr;

use crate::Runner;

use super::ThreadSafeDNSResolver;

mod handler;
pub use handler::exchange_with_resolver;

static DEFAULT_DNS_SERVER_TTL: u32 = 60;

struct DnsMessageExchanger {
    resolver: ThreadSafeDNSResolver,
}

impl watfaq_dns::DnsMessageExchanger for DnsMessageExchanger {
    fn ipv6(&self) -> bool {
        self.resolver.ipv6()
    }

    async fn exchange(
        &self,
        message: &Message,
    ) -> Result<Message, watfaq_dns::DNSError> {
        exchange_with_resolver(&self.resolver, message, true).await
    }
}

pub async fn get_dns_listener(
    listen: DNSListenAddr,
    resolver: ThreadSafeDNSResolver,
    cwd: &std::path::Path,
) -> Option<Runner> {
    let h = DnsMessageExchanger { resolver };
    let r = watfaq_dns::get_dns_listener(listen, h, cwd).await;
    match r {
        Some(r) => Some(Box::pin(async move {
            match r.await {
                Ok(()) => Ok(()),
                Err(err) => {
                    error!("dns listener error: {}", err);
                    Err(err.into())
                }
            }
        })),
        _ => None,
    }
}
