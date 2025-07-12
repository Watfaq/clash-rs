use std::{net::SocketAddr, time::Duration};

use crate::{
    app::net::OutboundInterface,
    proxy::utils::{new_tcp_stream, new_udp_socket},
};
use hickory_proto::runtime::{
    RuntimeProvider, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd,
};
use tokio::net::UdpSocket as TokioUdpSocket;

#[derive(Clone)]
pub struct DnsRuntimeProvider {
    handle: TokioHandle,
    iface: Option<OutboundInterface>,
    so_mark: Option<u32>,
}

impl DnsRuntimeProvider {
    pub fn new(iface: Option<OutboundInterface>, so_mark: Option<u32>) -> Self {
        Self {
            handle: TokioHandle::default(),
            iface,
            so_mark,
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
        server_addr: SocketAddr,
        // ignored: self.iface is used
        _bind_addr: Option<SocketAddr>,
        _timeout: Option<Duration>,
    ) -> std::pin::Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>>
    {
        let iface = self.iface.clone();
        let _so_mark = self.so_mark;
        Box::pin(async move {
            new_tcp_stream(
                server_addr,
                iface.as_ref(),
                #[cfg(target_os = "linux")]
                _so_mark,
            )
            .await
            .map(AsyncIoTokioAsStd)
        })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> std::pin::Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>>
    {
        let iface = self.iface.clone();
        let _so_mark = self.so_mark;
        Box::pin(async move {
            new_udp_socket(
                None,
                iface.as_ref(),
                #[cfg(target_os = "linux")]
                _so_mark,
            )
            .await
        })
    }
}
