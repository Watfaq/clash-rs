use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
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

use super::{AnyOutboundHandler, CommonOption, ConnectorType, OutboundHandler, OutboundType};

use async_trait::async_trait;
use futures::TryFutureExt;

use ipnet::IpNet;
use rand::seq::SliceRandom;
use tokio::sync::OnceCell;
use tracing::debug;

mod device;
mod events;
mod keys;
mod ports;
mod stack;
mod wireguard;

pub struct HandlerOpts {
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
    pub allowed_ips: Option<Vec<String>>,
    pub reserved_bits: Option<Vec<u8>>,
}

struct Inner {
    device_manager: Arc<device::DeviceManager>,
    #[allow(unused)]
    wg_handle: tokio::task::JoinHandle<()>,
    #[allow(unused)]
    device_manager_handle: tokio::task::JoinHandle<()>,
}

pub struct Handler {
    opts: HandlerOpts,
    inner: OnceCell<Inner>,
}

impl Handler {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(opts: HandlerOpts) -> AnyOutboundHandler {
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
                let allowed_ips = self
                    .opts
                    .allowed_ips
                    .as_ref()
                    .map(|ips| {
                        ips.iter()
                            .map(|ip| {
                                ip.parse::<IpNet>().map_err(|e| {
                                    new_io_error(format!("invalid allowed ip: {}", e).as_str())
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
                    .unwrap_or_default();

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
                        source_peer_ip: self.opts.ip,
                        source_peer_ipv6: self.opts.ipv6,
                        keepalive_seconds: Some(10),
                        allowed_ips,
                        reserved_bits: match &self.opts.reserved_bits {
                            Some(bits) => {
                                if bits.len() >= 3 {
                                    [bits[0], bits[1], bits[2]]
                                } else {
                                    [0, 0, 0]
                                }
                            }
                            None => [0, 0, 0],
                        },
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
                    self.opts.ip,
                    self.opts.ipv6,
                    resolver,
                    if self.opts.remote_dns_resolve {
                        self.opts
                            .dns
                            .as_ref()
                            .map(|server| {
                                server
                                    .iter()
                                    .map(|s| (s.parse::<IpAddr>().unwrap(), 53).into())
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default()
                    } else {
                        vec![]
                    },
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
        let inner = self
            .initialize_inner(resolver.clone())
            .await
            .map_err(map_io_error)?;

        let ip = if self.opts.remote_dns_resolve
            && sess.destination.is_domain()
            && self.opts.dns.as_ref().is_some_and(|x| !x.is_empty())
        {
            debug!(
                "use remote dns to resolve domain: {}",
                sess.destination.host()
            );
            let server = self
                .opts
                .dns
                .as_ref()
                .unwrap()
                .choose(&mut rand::thread_rng())
                .unwrap();

            inner
                .device_manager
                .look_up_dns(
                    &sess.destination.host(),
                    (server.parse::<IpAddr>().unwrap(), 53).into(),
                )
                .await
                .ok_or(new_io_error("invalid remote address"))?
        } else {
            resolver
                .resolve(&sess.destination.host(), false)
                .map_err(map_io_error)
                .await?
                .ok_or(new_io_error("invalid remote address"))?
        };

        let remote = (ip, sess.destination.port()).into();

        let socket = inner.device_manager.new_tcp_socket(remote).await;
        let chained = ChainedStreamWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        _sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let inner = self
            .initialize_inner(resolver)
            .await
            .map_err(map_io_error)?;

        let socket = inner.device_manager.new_udp_socket().await;
        let chained = ChainedDatagramWrapper::new(socket);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }
}

#[cfg(all(test, not(ci)))]
mod tests {

    use crate::proxy::utils::test_utils::docker_runner::DockerTestRunnerBuilder;
    use crate::proxy::utils::test_utils::{config_helper::test_config_base_dir, Suite};

    use super::super::utils::test_utils::{consts::*, docker_runner::DockerTestRunner};
    use crate::proxy::utils::test_utils::run_test_suites_and_cleanup;

    use super::*;

    // see: https://github.com/linuxserver/docker-wireguard?tab=readme-ov-file#usage
    // we shouldn't run the wireguard server with host mode, or
    // the sysctl of `net.ipv4.conf.all.src_valid_mark` will fail
    async fn get_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let wg_config = test_config_dir.join("wg_config");
        // the following configs is in accordance with the config in `wg_config` dir
        DockerTestRunnerBuilder::new()
            .image(IMAGE_WG)
            .env(&[
                "PUID=1000",
                "PGID=1000",
                "TZ=Etc/UTC",
                "SERVERPORT=10002",
                "PEERS=1",
                "PEERDNS=auto",
                "INTERNAL_SUBNET=10.13.13.0",
                "ALLOWEDIPS=0.0.0.0/0",
            ])
            .mounts(&[(wg_config.to_str().unwrap(), "/config")])
            .sysctls(&[("net.ipv4.conf.all.src_valid_mark", "1")])
            .cap_add(&["NET_ADMIN"])
            .net_mode("bridge") // the default network mode for testing is `host`
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_wg() -> anyhow::Result<()> {
        let opts = HandlerOpts {
            name: "wg".to_owned(),
            common_opts: CommonOption::default(),
            server: "127.0.0.1".to_owned(),
            port: 10002,
            ip: Ipv4Addr::new(10, 13, 13, 2),
            ipv6: None,
            private_key: "KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=".to_owned(),
            public_key: "INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=".to_owned(),
            preshared_key: Some("+JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc=".to_owned()),
            remote_dns_resolve: false,
            dns: None,
            mtu: Some(1000),
            udp: true,
            allowed_ips: Some(vec!["0.0.0.0/0".to_owned()]),
            reserved_bits: None,
        };
        let handler = Handler::new(opts);

        // cannot run the ping pong test, since the wireguard server is running on bridge network mode
        // and the `net.ipv4.conf.all.src_valid_mark` is not supported in the host network mode
        // the latency test should be enough
        run_test_suites_and_cleanup(handler, get_runner().await?, &[Suite::Latency]).await
    }
}
