use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use futures::{Sink, SinkExt, Stream};
use tokio::sync::Mutex;
use tokio_util::sync::PollSender;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::{map_io_error, new_io_error},
    proxy::datagram::UdpPacket,
    session::Session,
    session::SocksAddr,
};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse,
};

const TAILSCALE_CLIENT_NAME: &str = "clash-rs";
const TAILSCALE_STATE_FILE_NAME: &str = "tailscale_state.json";

#[derive(Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub state_dir: Option<String>,
    pub auth_key: Option<String>,
    pub hostname: Option<String>,
    pub control_url: Option<String>,
    pub ephemeral: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    device: Mutex<Option<Arc<::tailscale::Device>>>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tailscale")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            device: Mutex::new(None),
        }
    }

    async fn get_device(&self) -> io::Result<Arc<::tailscale::Device>> {
        let mut guard = self.device.lock().await;
        if let Some(device) = guard.as_ref() {
            return Ok(Arc::clone(device));
        }

        let key_state = if self.opts.ephemeral {
            Default::default()
        } else if let Some(state_dir) = self.opts.state_dir.as_ref() {
            let state_file =
                PathBuf::from(state_dir).join(TAILSCALE_STATE_FILE_NAME);
            ::tailscale::load_key_file(
                state_file,
                ::tailscale::BadFormatBehavior::Error,
            )
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to initialize tailscale key state: {e}"
                ))
            })?
        } else {
            Default::default()
        };

        let mut config = ::tailscale::Config {
            key_state,
            ..Default::default()
        };
        config.client_name = Some(TAILSCALE_CLIENT_NAME.to_owned());
        config.requested_hostname = self.opts.hostname.clone();

        if let Some(control_url) = self.opts.control_url.as_ref() {
            config.control_server_url = control_url.parse().map_err(|e| {
                io::Error::other(format!("invalid tailscale control-url: {e}"))
            })?;
        }

        let device = Arc::new(
            ::tailscale::Device::new(&config, self.opts.auth_key.clone())
                .await
                .map_err(|e| {
                    io::Error::other(format!(
                        "failed to initialize tailscale-rs device: {e}"
                    ))
                })?,
        );
        *guard = Some(Arc::clone(&device));
        Ok(device)
    }
}

impl DialWithConnector for Handler {}

#[derive(Debug)]
struct TailscaleDatagramOutbound {
    send_tx: PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
}

impl TailscaleDatagramOutbound {
    fn new(socket: ::tailscale::UdpSocket, resolver: ThreadSafeDNSResolver) -> Self {
        let local_addr = socket.local_addr();
        let local_addr_socks: SocksAddr = local_addr.into();
        let prefer_ipv6 = local_addr.is_ipv6();
        let socket = Arc::new(socket);
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);

        {
            let socket = Arc::clone(&socket);
            let resolver = resolver.clone();
            tokio::spawn(async move {
                while let Some(pkt) = send_rx.recv().await {
                    let dst = match pkt.dst_addr {
                        SocksAddr::Ip(addr) => addr,
                        SocksAddr::Domain(domain, port) => {
                            let ip = if prefer_ipv6 {
                                resolver
                                    .resolve_v6(&domain, false)
                                    .await
                                    .map(|x| x.map(std::net::IpAddr::V6))
                            } else {
                                resolver
                                    .resolve_v4(&domain, false)
                                    .await
                                    .map(|x| x.map(std::net::IpAddr::V4))
                            };

                            let ip = match ip.map_err(map_io_error) {
                                Ok(Some(ip)) => ip,
                                Ok(None) => {
                                    tracing::warn!(
                                        "tailscale udp resolve returned no result for {domain}"
                                    );
                                    continue;
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        "tailscale udp resolve failed for {domain}: {err}"
                                    );
                                    continue;
                                }
                            };
                            (ip, port).into()
                        }
                    };

                    if let Err(err) = socket.send_to(dst, &pkt.data).await {
                        tracing::warn!(
                            "tailscale udp send_to failed for {dst}: {err}"
                        );
                        break;
                    }
                }
            });
        }

        tokio::spawn(async move {
            loop {
                let recv = socket.recv_from_bytes().await;
                let (remote, data) = match recv {
                    Ok(recv) => recv,
                    Err(err) => {
                        tracing::warn!("tailscale udp recv_from failed: {err}");
                        break;
                    }
                };

                if recv_tx
                    .send(UdpPacket {
                        data: data.into(),
                        src_addr: remote.into(),
                        dst_addr: local_addr_socks.clone(),
                        inbound_user: None,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Self {
            send_tx: PollSender::new(send_tx),
            recv_rx,
        }
    }
}

impl Sink<UdpPacket> for TailscaleDatagramOutbound {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|_| new_io_error("tailscale udp send channel not ready"))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|_| new_io_error("tailscale udp send channel closed"))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|_| new_io_error("tailscale udp send channel flush failed"))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|_| new_io_error("tailscale udp send channel close failed"))
    }
}

impl Stream for TailscaleDatagramOutbound {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tailscale
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let remote_ip = resolver
            .resolve(sess.destination.host().as_str(), false)
            .await
            .map_err(map_io_error)?
            .ok_or_else(|| io::Error::other("no dns result"))?;
        let device = self.get_device().await?;
        let s = device
            .tcp_connect((remote_ip, sess.destination.port()).into())
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to connect over tailscale-rs to {}:{}: {e}",
                    remote_ip,
                    sess.destination.port()
                ))
            })?;

        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let device = self.get_device().await?;
        let local_ip: std::net::IpAddr = if sess.source.is_ipv4() {
            device
                .ipv4_addr()
                .await
                .map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale ipv4 address: {e}"
                    ))
                })?
                .into()
        } else {
            device
                .ipv6_addr()
                .await
                .map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale ipv6 address: {e}"
                    ))
                })?
                .into()
        };
        let udp = device.udp_bind((local_ip, 0).into()).await.map_err(|e| {
            io::Error::other(format!(
                "failed to bind tailscale udp socket on {local_ip}: {e}"
            ))
        })?;

        let d = TailscaleDatagramOutbound::new(udp, resolver);
        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("name".to_owned(), Box::new(self.opts.name.clone()) as _);
        m.insert("type".to_owned(), Box::new(self.proto().to_string()) as _);
        m.insert(
            "state-dir".to_owned(),
            Box::new(self.opts.state_dir.clone()) as _,
        );
        m.insert(
            "hostname".to_owned(),
            Box::new(self.opts.hostname.clone()) as _,
        );
        m.insert(
            "control-url".to_owned(),
            Box::new(self.opts.control_url.clone()) as _,
        );
        m.insert("ephemeral".to_owned(), Box::new(self.opts.ephemeral) as _);
        m.insert(
            "auth-key-set".to_owned(),
            Box::new(self.opts.auth_key.is_some()) as _,
        );
        m
    }
}

#[cfg(test)]
mod tests {
    use super::{Handler, HandlerOptions};
    use crate::proxy::{OutboundHandler, PlainProxyAPIResponse};

    #[tokio::test]
    async fn tailscale_support_udp_is_enabled() {
        let h = Handler::new(HandlerOptions {
            name: "ts".to_owned(),
            state_dir: None,
            auth_key: None,
            hostname: None,
            control_url: None,
            ephemeral: false,
        });
        assert!(h.support_udp().await);
    }

    #[tokio::test]
    async fn tailscale_api_response_redacts_auth_key() {
        let h = Handler::new(HandlerOptions {
            name: "ts".to_owned(),
            state_dir: None,
            auth_key: Some("tskey-auth-xxxx".to_owned()),
            hostname: None,
            control_url: None,
            ephemeral: false,
        });
        let map = h.as_map().await;
        assert!(
            map.contains_key("auth-key-set"),
            "auth-key-set should be present"
        );
        assert!(
            !map.contains_key("auth-key"),
            "raw auth-key must not be present"
        );
    }

    #[tokio::test]
    #[ignore = "requires TS_AUTH_KEY for live tailscale auth"]
    async fn tailscale_live_auth_key_can_initialize_device() {
        let auth_key = match std::env::var("TS_AUTH_KEY") {
            Ok(v) if !v.is_empty() => v,
            _ => return,
        };

        let state_dir = tempfile::tempdir().expect("temp state dir");
        let h = Handler::new(HandlerOptions {
            name: "ts-live-auth".to_owned(),
            state_dir: Some(state_dir.path().to_string_lossy().into_owned()),
            auth_key: Some(auth_key),
            hostname: None,
            control_url: None,
            ephemeral: false,
        });

        let device = h
            .get_device()
            .await
            .expect("tailscale device should initialize with TS_AUTH_KEY");
        let addr = device
            .ipv4_addr()
            .await
            .expect("tailscale device should acquire an IPv4 address");
        assert!(
            !addr.is_unspecified(),
            "tailscale device returned an unspecified IPv4 address"
        );
    }
}
