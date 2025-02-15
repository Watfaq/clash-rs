use std::{net::SocketAddr, time::Duration};

use crate::proxy::utils::{new_tcp_stream, new_udp_socket, Interface};
use hickory_proto::runtime::{
    iocompat::AsyncIoTokioAsStd, RuntimeProvider, TokioHandle, TokioTime,
};
use tokio::net::UdpSocket as TokioUdpSocket;

#[derive(Clone)]
pub struct DnsRuntimeProvider {
    handle: TokioHandle,
    iface: Option<Interface>,
}

impl DnsRuntimeProvider {
    pub fn new(iface: Option<Interface>) -> Self {
        Self {
            handle: TokioHandle::default(),
            iface,
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

    // TODO: move this timeout into new_tcp_stream
    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        // ignored: self.iface is taken
        _bind_addr: Option<SocketAddr>,
        _timeout: Option<Duration>,
    ) -> std::pin::Pin<
        Box<
            dyn Send
                + std::prelude::rust_2024::Future<Output = std::io::Result<Self::Tcp>>,
        >,
    > {
        let iface = self.iface.clone();
        Box::pin(async move {
            new_tcp_stream(
                server_addr,
                iface,
                #[cfg(target_os = "linux")]
                None,
            )
            .await
            .map(AsyncIoTokioAsStd)
        })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> std::pin::Pin<
        Box<
            dyn Send
                + std::prelude::rust_2024::Future<Output = std::io::Result<Self::Udp>>,
        >,
    > {
        let iface = self.iface.clone();
        Box::pin(async move {
            new_udp_socket(
                None,
                iface.clone(),
                #[cfg(target_os = "linux")]
                None,
            )
            .await
        })
    }
}
