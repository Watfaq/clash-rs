use std::{net::SocketAddr, sync::Arc, time::Duration};

use hickory_proto::runtime::{
    RuntimeProvider, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd,
};
use tokio::net::UdpSocket as TokioUdpSocket;
use watfaq_state::Context;

#[derive(Clone)]
pub struct DnsRuntimeProvider {
    handle: TokioHandle,
    ctx: Arc<Context>,
}

impl DnsRuntimeProvider {
    pub fn new(ctx: Arc<Context>) -> Self {
        Self {
            handle: TokioHandle::default(),
            ctx,
        }
    }
}

impl RuntimeProvider for DnsRuntimeProvider {
    type Handle = TokioHandle;
    type Tcp = AsyncIoTokioAsStd<tokio::net::TcpStream>;
    type Timer = TokioTime;
    type Udp = TokioUdpSocket;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        // FIXME checkout how this is decided
        server_addr: SocketAddr,
        // ignored: self.iface is taken
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> std::pin::Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>>
    {
        let ctx = self.ctx.clone();
        Box::pin(async move {
            ctx.protector
                .new_tcp(server_addr, timeout)
                .await
                .map(AsyncIoTokioAsStd)
                .map_err(|e| std::io::Error::other(e))
        })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> std::pin::Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>>
    {
        let ctx = self.ctx.clone();
        Box::pin(async move {
            ctx.clone()
                .protector
                .new_udp(server_addr)
                .await
                .map_err(|e| std::io::Error::other(e))
        })
    }
}
