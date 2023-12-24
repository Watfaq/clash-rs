use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::{
    app::dispatcher::{
        ChainedDatagram, ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
    },
    Error,
};
use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
    },
    common::errors::{map_io_error, new_io_error},
    session::{Session, SocksAddr},
};

use self::{keys::KeyBytes, wireguard::Config};

use super::{AnyOutboundHandler, AnyStream, CommonOption, OutboundHandler, OutboundType};

use async_trait::async_trait;
use futures::TryFutureExt;

use tokio::sync::OnceCell;

mod device;
mod events;
mod keys;
mod ports;
mod stack;
mod wireguard;

pub struct Opts {
    pub name: String,
    pub common_opts: CommonOption,
    pub server: String,
    pub port: u16,
    pub ip: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub private_key: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub remote_dns_resolve: bool,
    pub dns: Option<Vec<String>>,
    pub mtu: Option<u16>,
    pub udp: bool,
}

struct Inner {
    device_manager: Arc<device::DeviceManager>,
    #[allow(unused)]
    wg_handle: tokio::task::JoinHandle<()>,
    #[allow(unused)]
    device_manager_handle: tokio::task::JoinHandle<()>,
}

pub struct Handler {
    opts: Opts,
    inner: OnceCell<Inner>,
}

impl Handler {
    pub fn new(opts: Opts) -> AnyOutboundHandler {
        Arc::new(Self {
            opts,
            inner: OnceCell::new(),
        })
    }

    async fn initialize_inner(&self, resolver: ThreadSafeDNSResolver) -> Result<&Inner, Error> {
        self.inner
            .get_or_try_init(|| async {
                let recv_pair = tokio::sync::mpsc::channel(1024);
                let send_pair = tokio::sync::mpsc::channel(1024);
                let server_ip = resolver
                    .resolve(&self.opts.server, false)
                    .await
                    .map_err(map_io_error)?
                    .ok_or(new_io_error(
                        format!("invalid remote server: {}", self.opts.server).as_str(),
                    ))?;

                // we shouldn't create a new tunnel for each connection
                let wg = wireguard::WireguardTunnel::new(
                    Config {
                        private_key: self.opts.private_key.parse::<KeyBytes>().unwrap().0.into(),
                        endpoint_public_key: self
                            .opts
                            .public_key
                            .parse::<KeyBytes>()
                            .unwrap()
                            .0
                            .into(),
                        preshared_key: self
                            .opts
                            .preshared_key
                            .as_ref()
                            .map(|s| s.parse::<KeyBytes>().unwrap().0.into()),
                        remote_endpoint: (server_ip, self.opts.port).into(),
                        source_peer_ip: self
                            .opts
                            .ipv6
                            .map(|ip| ip.into())
                            .unwrap_or(self.opts.ip.into()),
                        keepalive_seconds: Some(10),
                    },
                    recv_pair.0,
                    send_pair.1,
                )
                .await
                .map_err(map_io_error)?;

                let wg_handle = tokio::spawn(async move {
                    wg.start_polling().await;
                });

                // use to notify the device manager to poll sockets
                let packet_notifier = tokio::sync::mpsc::channel(1024);

                let device = device::VirtualIpDevice::new(
                    send_pair.0,
                    recv_pair.1,
                    packet_notifier.0,
                    self.opts.mtu.unwrap_or(1420) as usize,
                );

                let device_manager = Arc::new(device::DeviceManager::new(
                    self.opts.ip.into(),
                    packet_notifier.1,
                ));

                let device_manager_clone = device_manager.clone();
                let device_manager_handle = tokio::spawn(async move {
                    device_manager_clone.poll_sockets(device).await;
                });

                Ok(Inner {
                    device_manager,
                    wg_handle,
                    device_manager_handle,
                })
            })
            .await
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::WireGuard
    }

    async fn remote_addr(&self) -> Option<SocksAddr> {
        Some(SocksAddr::Domain(self.opts.server.clone(), self.opts.port))
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let ip = resolver
            .resolve(&sess.destination.host(), false)
            .map_err(map_io_error)
            .await?
            .ok_or(new_io_error("invalid remote address"))?;
        let remote = (ip, sess.destination.port()).into();

        let inner = self
            .initialize_inner(resolver)
            .await
            .map_err(map_io_error)?;

        let socket = inner.device_manager.new_tcp_socket(remote).await;
        let chained = ChainedStreamWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    /// wraps a stream with outbound handler
    async fn proxy_stream(
        &self,
        _s: AnyStream,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        Err(new_io_error("not supported"))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let ip = resolver
            .resolve(&sess.destination.host(), false)
            .map_err(map_io_error)
            .await?
            .ok_or(new_io_error("invalid remote address"))?;

        let remote = (ip, sess.destination.port()).into();

        let inner = self
            .initialize_inner(resolver)
            .await
            .map_err(map_io_error)?;

        let socket = inner.device_manager.new_udp_socket(remote).await;
        let chained = ChainedDatagramWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}
