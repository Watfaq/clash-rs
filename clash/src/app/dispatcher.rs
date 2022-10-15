use crate::app::outbound::manager::ThreadSafeOutboundManager;
use crate::app::router::ThreadSafeRouter;
use crate::app::ThreadSafeDNSResolver;
use crate::proxy::AnyStream;
use crate::session::Session;

use log::{debug, info, warn};
use std::io;

use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt};

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

    pub async fn dispatch_stream<S>(&self, mut sess: Session, mut lhs: Box<S>)
    where
        S: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
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

        info!("{} matched rule {}", sess, handler.name());

        match handler.connect_stream(&sess, self.dns_client.clone()).await {
            Ok(mut rhs) => {
                info!("remote connection established {}", sess);
                match copy_bidirectional(&mut lhs, &mut rhs).await {
                    Ok((up, down)) => {
                        info!(
                            "connection {} closed with {} bytes up, {} bytes down",
                            sess, up, down
                        );
                    }
                    Err(err) => {
                        warn!("connection {} closed with error {}", sess, err)
                    }
                }
            }
            Err(err) => {
                warn!(
                    "failed to establish remote connection {}, error: {}",
                    sess, err
                );
                if let Err(e) = lhs.shutdown().await {
                    warn!("error closing local connection {}: {}", sess, err)
                }
            }
        }
    }
}
