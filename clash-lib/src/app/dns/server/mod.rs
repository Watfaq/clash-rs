use hickory_proto::op::Message;

use tracing::{error, info, instrument};
use watfaq_dns::DNSListenAddr;

use crate::runner::Runner;

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

    #[instrument(skip(self))]
    async fn exchange(
        &self,
        message: &Message,
    ) -> Result<Message, watfaq_dns::DNSError> {
        exchange_with_resolver(&self.resolver, message, true).await
    }
}

pub struct DnsRunner {
    listener: DNSListenAddr,
    resolver: ThreadSafeDNSResolver,
    cwd: std::path::PathBuf,

    cancellation_token: tokio_util::sync::CancellationToken,
}

impl DnsRunner {
    pub fn new(
        listen: DNSListenAddr,
        resolver: ThreadSafeDNSResolver,
        cwd: &std::path::Path,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            listener: listen,
            resolver,
            cwd: cwd.to_path_buf(),
            cancellation_token: cancellation_token.unwrap_or_default(),
        }
    }
}

impl Runner for DnsRunner {
    fn run(&self) -> futures::future::BoxFuture<'_, Result<(), crate::Error>> {
        let resolver = self.resolver.clone();
        let listen = self.listener.clone();
        let cwd = self.cwd.clone();
        let cancellation_token = self.cancellation_token.clone();

        Box::pin(async move {
            let h = DnsMessageExchanger { resolver };
            let r = watfaq_dns::get_dns_listener(listen, h, &cwd).await;
            if let Some(r) = r {
                tokio::select! {
                    res = r => {
                        match res {
                            Ok(()) => Ok(()),
                            Err(err) => {
                                error!("dns listener error: {}", err);
                                Err(err.into())
                            }
                        }
                    },
                    _ = cancellation_token.cancelled() => {
                        info!("dns listener is closed");
                        Ok(())
                    },
                }
            } else {
                Err(crate::Error::InvalidConfig(
                    "failed to start dns listener: no valid listen address".into(),
                ))
            }
        })
    }

    fn shutdown(&self) -> futures::future::BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move {
            self.cancellation_token.cancel();
            Ok(())
        })
    }

    fn join(&self) -> futures::future::BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move { Ok(()) })
    }
}
