use crate::app::outbound::manager::ThreadSafeOutboundManager;
use crate::app::router::ThreadSafeRouter;
use crate::app::ThreadSafeDNSResolver;
use crate::proxy::AnyStream;
use crate::session::Session;

use std::io;

use tokio::io::{copy_bidirectional, AsyncWriteExt};

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ThreadSafeRouter,
    dns_client: ThreadSafeDNSResolver,
}

impl Dispatcher {
    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        router: ThreadSafeRouter,
        dns_client: ThreadSafeDNSResolver,
    ) -> Self {
        Self {
            outbound_manager,
            router,
            dns_client,
        }
    }

    pub async fn dispatch_stream(&self, mut sess: Session, mut lhs: AnyStream) {
        let outbound_name = self
            .router
            .read()
            .await
            .match_route(&sess)
            .await
            .to_string();
        sess.outbound_target = outbound_name.to_string();
        let handler = self
            .outbound_manager
            .read()
            .await
            .get(outbound_name.as_str())
            .expect(format!("unknown rule: {}", outbound_name).as_str()); // should never happen

        match handler.connect_stream(&sess, self.dns_client.clone()).await {
            Ok(mut rhs) => match copy_bidirectional(&mut lhs, &mut rhs).await {
                Ok(_) => {}
                Err(_) => {}
            },
            Err(_) => if let Err(_e) = lhs.shutdown().await {},
        }
    }
}
