use crate::app::outbound::manager::ThreadSafeOutboundManager;
use crate::app::router::ThreadSafeRouter;
use crate::app::ThreadSafeDNSResolver;
use crate::proxy::datagram::UdpPacket;
use crate::proxy::{utils, AnyOutboundDatagram, ProxyError};
use crate::session::Session;

use futures::Stream;
use futures::{Sink, StreamExt};
use log::{error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ThreadSafeRouter,
    resolver: ThreadSafeDNSResolver,
    outbound_mapping: Arc<Mutex<HashMap<String, bool>>>,
}

impl Dispatcher {
    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        router: ThreadSafeRouter,
        resolver: ThreadSafeDNSResolver,
    ) -> Self {
        Self {
            outbound_manager,
            router,
            resolver,
            outbound_mapping: Arc::new(Mutex::new(HashMap::new())),
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

        match handler.connect_stream(&sess, self.resolver.clone()).await {
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

    pub async fn dispatch_datagram<U>(&self, sess: Session, mut udp_inbound: U)
    where
        U: Stream<Item = UdpPacket> + Sink<UdpPacket, Error = std::io::Error> + Unpin + Send,
    {
        let orig_src = sess.source;
        let router = self.router.clone();
        let outbound_manager = self.outbound_manager.clone();
        let outbound_handlers_map = self.outbound_mapping.clone();
        let resolver = self.resolver.clone();

        while let Some(packet) = udp_inbound.next().await {
            let mut sess = sess.clone();
            sess.destination = packet.dst_addr.clone();
            let outbound_name = router.read().await.match_route(&sess).await.to_string();

            let handler = outbound_manager
                .read()
                .await
                .get(outbound_name.as_str())
                .expect(format!("unknown rule: {}", outbound_name).as_str());

            info!("{} matched rule {}", sess, handler.name());

            let mut outbound_handle_guard = outbound_handlers_map.lock().await;

            match outbound_handle_guard.get(&outbound_name) {
                None => {
                    let mut outbound_datagram =
                        match handler.connect_datagram(&sess, resolver.clone()).await {
                            Ok(v) => v,
                            Err(err) => {
                                error!("failed to connect outbound: {}", err);
                                return;
                            }
                        };

                    outbound_handle_guard.insert(outbound_name, true);
                    match utils::copy_bidirectional(&mut udp_inbound, &mut outbound_datagram).await
                    {
                        Ok(val) => {
                            info!(
                                "connection {} closed with {} packets up, {} packets down",
                                sess, val.0, val.1
                            );
                        }
                        Err(err) => {
                            error!("connection {} closed with error {}", sess, err);
                        }
                    }
                }
                Some(outbound_datagram) => {}
            };
        }
    }
}
