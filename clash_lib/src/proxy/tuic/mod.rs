use crate::{
    common::tls::DefaultTlsVerifier,
    proxy::{tuic::types::SocketAdderTrans, utils::new_udp_socket},
};

use arc_swap::ArcSwap;
use async_trait::async_trait;

use watfaq_state::Context;

use crate::{
    app::dispatcher::{
        BoxedChainedDatagram, BoxedChainedStream, ChainedStream,
        ChainedStreamWrapper,
    },
    proxy::DialWithConnector,
    session::Session,
};

use super::{ConnectorType, OutboundHandler, OutboundType};

impl DialWithConnector for watfaq_tuic::Handler {}

#[async_trait]
impl OutboundHandler for watfaq_tuic::Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tuic
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        ctx: ArcSwap<Context>,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        async {
            let conn = self.get_conn(&ctx.load(), &resolver, sess).await?;
            let dest = sess.destination.clone().into_tuic();
            let tuic_tcp = conn.connect_tcp(dest).await?;
            let s = ChainedStreamWrapper::new(tuic_tcp);
            s.append_to_chain(self.name()).await;
            Ok(Box::new(s))
        }
        .await
        .map_err(|e| {
            tracing::error!("{:?}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })?
    }

    async fn connect_datagram(
        &self,
        ctx: ArcSwap<Context>,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        self.do_connect_datagram(sess, resolver).await.map_err(|e| {
            tracing::error!("{:?}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }
}
