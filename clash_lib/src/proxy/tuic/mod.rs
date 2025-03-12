use std::sync::atomic::Ordering;

use async_trait::async_trait;
use watfaq_error::Result;

use crate::{
    app::dispatcher::{
        BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
        ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
    },
    session::Session,
};

use super::{AbstractOutboundHandler, ConnectorType, OutboundType};
use watfaq_tuic::types::SocketAdderTrans;

#[async_trait]
impl AbstractOutboundHandler for watfaq_tuic::Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tuic
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(&self, sess: &Session) -> Result<BoxedChainedStream> {
        let conn = self.get_conn(self.ctx(), self.resolver()).await?;
        let dest = sess.destination.clone().into_tuic();
        let tuic_tcp = conn.connect_tcp(dest).await?;
        let s = ChainedStreamWrapper::new(tuic_tcp);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
    ) -> Result<BoxedChainedDatagram> {
        let conn = self.get_conn(self.ctx(), self.resolver()).await?;
        let assos_id = self.next_assoc_id.fetch_add(1, Ordering::SeqCst);
        let tuic_udp =
            watfaq_tuic::TuicUdpOutbound::new(assos_id, conn, sess.source.into());
        let s = ChainedDatagramWrapper::new(tuic_udp);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }
}
