use crate::proxy::{AnyOutboundHandler, AnyStream, OutboundConnect, OutboundStreamHandler};
use crate::session::{Session, SocksAddr};
use async_trait::async_trait;
use tokio::io::AsyncReadExt;

pub struct Handler {
    pub inner_handlers: Vec<AnyOutboundHandler>,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        for h in self.inner_handlers.iter() {
            let mut new_sess = sess.clone();
            new_sess.destination = match h.stream()?.connect_addr() {
                OutboundConnect::Proxy(network, addr, port) => (addr, port).try_into()?,
                OutboundConnect::None => new_sess.destination,
            };
            stream = h.stream()?.handle(&new_sess, stream).await?;
        }
        Ok(stream)
    }
}
