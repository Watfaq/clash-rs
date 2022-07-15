use crate::app::outbound::manager::{OutboundManager, ThreadSafeOutboundManager};
use crate::app::router::{Router, ThreadSafeRouter};
use crate::app::ThreadSafeAsyncDnsClient;
use crate::proxy::{AnyOutboundDatagram, AnyStream};
use crate::session::Session;
use std::future::Future;
use std::io;
use std::io::Error;
use std::sync::{Arc, RwLock};
use std::thread::Thread;
use tokio::io::{copy_bidirectional, AsyncWriteExt};

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ThreadSafeRouter,
    dns_client: ThreadSafeAsyncDnsClient,
}

impl Dispatcher {
    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        router: ThreadSafeRouter,
        dns_client: ThreadSafeAsyncDnsClient,
    ) -> Self {
        Self {
            outbound_manager,
            router,
            dns_client,
        }
    }

    pub async fn dispatch_stream(&self, mut sess: Session, mut lhs: AnyStream) {
        let outbound_name = self.router.read().await.match_route(&sess).await;
        sess.outbound_target = outbound_name.to_string();
        let handler = self
            .outbound_manager
            .read()
            .await
            .get(outbound_name)
            .expect(format!("unknown rule: {}", outbound_name).as_str()); // should never happen

        match handler.handle_tcp(&sess).await {
            Ok(mut rhs) => match copy_bidirectional(&mut lhs, &mut rhs).await {
                Ok(_) => {}
                Err(_) => {}
            },
            Err(_) => {
                lhs.shutdown().await?;
            }
        }
    }

    pub async fn dispatch_datagram(&self, mut sess: Session) -> io::Result<AnyOutboundDatagram> {
        let outbound_name = self.router.read().await.match_route(&sess).await;
        sess.outbound_target = outbound_name.to_string();
        let handler = self
            .outbound_manager
            .read()
            .await
            .get(outbound_name)
            .expect(format!("unknown rule: {}", outbound_name).as_str());
        handler.handle_udp(&sess, self.dns_client).await
    }
}
