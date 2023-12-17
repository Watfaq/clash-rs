use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::app::dispatcher::{ChainedStream, ChainedStreamWrapper};
use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
    },
    common::errors::{map_io_error, new_io_error},
    session::{Session, SocksAddr},
};

use self::{keys::KeyBytes, stack::VirtualInterfacePoll, wireguard::Config};

use super::{AnyOutboundHandler, AnyStream, CommonOption, OutboundHandler, OutboundType};

use async_trait::async_trait;
use futures::TryFutureExt;

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

pub struct Handler {
    opts: Opts,
}

impl Handler {
    pub fn new(opts: Opts) -> AnyOutboundHandler {
        Arc::new(Self { opts })
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

        let stack = stack::tcp::TcpSocketStack::new(
            self.opts
                .ipv6
                .map(|ip| IpAddr::V6(ip))
                .unwrap_or(IpAddr::V4(self.opts.ip)),
            (ip, sess.destination.port()).into(),
        );

        let socket = stack.get_socket_pair();

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
                endpoint_public_key: self.opts.public_key.parse::<KeyBytes>().unwrap().0.into(),
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

        tokio::spawn(async move {
            wg.start_polling().await;
        });

        let device = device::VirtualIpDevice::new(
            send_pair.0,
            recv_pair.1,
            self.opts.mtu.unwrap_or(1420) as usize,
        );

        tokio::spawn(stack.poll_loop(device));

        let chained = ChainedStreamWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    /// wraps a stream with outbound handler
    async fn proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        todo!()
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        todo!()
    }
}
