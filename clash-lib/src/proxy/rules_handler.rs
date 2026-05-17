//! A special outbound handler used when `respect-rules` is enabled in the DNS
//! configuration.
//!
//! When `respect-rules: true`, DNS nameserver connections should be routed
//! through the rule engine instead of connecting directly.  The DNS client is
//! created with proxy name `"RULES"`, which resolves to a
//! `SharedOutboundHandler`.  At connection time the `SharedOutboundHandler`
//! looks up `"RULES"` in the outbound registry and finds this handler.
//!
//! `RulesOutboundHandler` mirrors a subset of `Dispatcher::dispatch_stream` /
//! `dispatch_datagram`: it resolves the destination, matches it against the
//! routing rules via the `Router`, picks the appropriate outbound from the
//! `OutboundManager`, and delegates the actual connect to that outbound.

use async_trait::async_trait;
use tracing::{debug, instrument, warn};

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        outbound::manager::ThreadSafeOutboundManager,
        router::ArcRouter,
    },
    config::internal::proxy::PROXY_DIRECT,
    proxy::{ConnectorType, DialWithConnector, OutboundHandler, OutboundType},
    session::{Session, SocksAddr},
};

pub struct RulesOutboundHandler {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
}

impl RulesOutboundHandler {
    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        router: ArcRouter,
    ) -> Self {
        Self {
            outbound_manager,
            router,
        }
    }

    async fn resolve_dest(
        resolver: &ThreadSafeDNSResolver,
        dest: &SocksAddr,
    ) -> Option<SocksAddr> {
        match dest {
            SocksAddr::Domain(domain, port) => {
                match resolver.resolve(domain, false).await {
                    Ok(Some(ip)) => {
                        let addr = std::net::SocketAddr::new(ip, *port);
                        Some(SocksAddr::Ip(addr))
                    }
                    Ok(None) => {
                        warn!(
                            "rules-handler: failed to resolve domain \
                             {domain}"
                        );
                        None
                    }
                    Err(e) => {
                        warn!(
                            "rules-handler: DNS resolve error for \
                             {domain}: {e}"
                        );
                        None
                    }
                }
            }
            SocksAddr::Ip(_) => Some(dest.clone()),
        }
    }

    async fn get_handler(
        &self,
        name: &str,
    ) -> Option<crate::proxy::AnyOutboundHandler> {
        match self.outbound_manager.get_outbound(name).await {
            Some(h) => Some(h),
            None => {
                warn!(
                    "rules-handler: outbound '{name}' not found, falling \
                     back to DIRECT"
                );
                self.outbound_manager.get_outbound(PROXY_DIRECT).await
            }
        }
    }

    /// Resolve the destination and match it against routing rules.
    /// Returns the name of the outbound to use.
    async fn route(
        &self,
        sess: &Session,
        resolver: &ThreadSafeDNSResolver,
    ) -> String {
        let dest = match Self::resolve_dest(resolver, &sess.destination).await
        {
            Some(d) => d,
            None => {
                debug!(
                    "rules-handler: could not resolve destination {}, \
                     falling back to DIRECT",
                    sess.destination
                );
                return PROXY_DIRECT.to_string();
            }
        };

        let mut route_sess = sess.clone();
        route_sess.destination = dest;
        let (outbound_name, _) =
            self.router.match_route(&mut route_sess).await;
        outbound_name.to_string()
    }
}

impl std::fmt::Debug for RulesOutboundHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RulesOutboundHandler").finish()
    }
}

#[async_trait]
impl DialWithConnector for RulesOutboundHandler {}

#[async_trait]
impl OutboundHandler for RulesOutboundHandler {
    fn name(&self) -> &str {
        crate::app::dns::config::RESPECT_RULES
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Direct
    }

    async fn support_udp(&self) -> bool {
        // UDP support depends on the resolved outbound; optimistically true
        true
    }

    #[instrument(skip(self, sess, resolver), level = "debug")]
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let outbound_name = self.route(sess, &resolver).await;

        debug!(
            "rules-handler: routing TCP {} via outbound '{}'",
            sess.destination, outbound_name
        );

        let handler = match self.get_handler(&outbound_name).await {
            Some(h) => h,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("outbound '{outbound_name}' not found"),
                ));
            }
        };

        handler.connect_stream(sess, resolver).await
    }

    #[instrument(skip(self, sess, resolver), level = "debug")]
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let outbound_name = self.route(sess, &resolver).await;

        debug!(
            "rules-handler: routing UDP {} via outbound '{}'",
            sess.destination, outbound_name
        );

        let handler = match self.get_handler(&outbound_name).await {
            Some(h) => h,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("outbound '{outbound_name}' not found"),
                ));
            }
        };

        handler.connect_datagram(sess, resolver).await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }
}
