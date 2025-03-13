use std::sync::Arc;

use hickory_proto::op::Message;
use tokio::net::UdpSocket;
use tracing::info;
use watfaq_dns::{DNSListenAddr, get_dns_listener};
use watfaq_resolver::Resolver;

pub use crate::{
    app::api::controller_task as build_controller_task,
    proxy::tun::setup_tun_module as build_tun_task,
};

pub async fn build_dns_task(
    listen: DNSListenAddr,
    resolver: Arc<Resolver>,
    cwd: &std::path::Path,
) -> watfaq_error::Result<()> {
    match get_dns_listener(listen, self::dns::DnsExchangerCompat { resolver }, cwd)
        .await
    {
        Some(fut) => fut.await?,
        None => {}
    }
    Ok(())
}

mod dns {
    use hickory_proto::op::Message;
    use std::sync::Arc;
    use watfaq_resolver::{Resolver, exchange_with_resolver};

    pub(crate) struct DnsExchangerCompat {
        pub(crate) resolver: Arc<Resolver>,
    }

    impl watfaq_dns::DnsMessageExchanger for DnsExchangerCompat {
        fn ipv6(&self) -> bool {
            true //todo
        }

        async fn exchange(
            &self,
            message: &Message,
        ) -> Result<Message, watfaq_dns::DNSError> {
            let msg = exchange_with_resolver(&self.resolver, message, true).await?;
            Ok(msg)
        }
    }
}
