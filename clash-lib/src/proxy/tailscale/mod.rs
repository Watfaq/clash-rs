mod datagram;

use datagram::TailscaleDatagramOutbound;

use std::{
    collections::HashMap, fmt::Debug, io, net::IpAddr, path::PathBuf, sync::Arc,
};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use tokio::sync::Mutex;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::map_io_error,
    session::{Session, SocksAddr},
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
    pub client_name: Option<String>,
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

    /// Lazily initialise and return the shared [`tailscale::Device`].
    ///
    /// **State persistence**: when `state_dir` is set the device identity is
    /// loaded from (and automatically written back to) a JSON file so it
    /// survives process restarts.  When `state_dir` is `None` the identity is
    /// held in memory only; the device will register a fresh node on every
    /// startup unless `ephemeral: true` is also set.
    async fn get_device(&self) -> io::Result<Arc<::tailscale::Device>> {
        let mut guard = self.device.lock().await;
        if let Some(device) = guard.as_ref() {
            return Ok(Arc::clone(device));
        }

        let key_state = if self.opts.ephemeral {
            Default::default()
        } else if let Some(state_dir) = self.opts.state_dir.as_ref() {
            // load_key_file reads persisted key material so the device keeps
            // the same Tailscale identity across restarts.  The tailscale-rs
            // crate writes updated state back to the file automatically while
            // the Device is alive; no explicit save step is required.
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
            // ephemeral: false but no state_dir — identity is in-memory only
            // and will be lost when the process exits.  Log so users are aware.
            tracing::warn!(
                name = %self.opts.name,
                "tailscale: ephemeral is false but no state-dir is configured; \
                 device identity will not be persisted across restarts"
            );
            Default::default()
        };

        let mut config = ::tailscale::Config {
            key_state,
            ..Default::default()
        };
        config.client_name = Some(
            self.opts
                .client_name
                .as_deref()
                .unwrap_or(TAILSCALE_CLIENT_NAME)
                .to_owned(),
        );
        config.requested_hostname = self.opts.hostname.clone();

        if let Some(control_url) = self.opts.control_url.as_ref() {
            config.control_server_url = control_url.parse().map_err(|e| {
                io::Error::other(format!("invalid tailscale control-url: {e}"))
            })?;
        }

        // tailscale-rs requires this env var as an acknowledgement that the
        // crate is experimental.  Set it on behalf of the user so they don't
        // need to configure it themselves.
        // SAFETY: single-threaded point inside a Mutex-guarded lazy-init block;
        // no other thread is reading or writing this variable concurrently.
        unsafe {
            std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software");
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
        let remote_ip = match &sess.destination {
            SocksAddr::Ip(addr) => addr.ip(),
            SocksAddr::Domain(host, _) => resolver
                .resolve(host, false)
                .await
                .map_err(map_io_error)?
                .ok_or_else(|| io::Error::other("no dns result"))?,
        };
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
        let local_ip: IpAddr = match &sess.destination {
            // Strict: IP literal family must match — fail fast rather than binding
            // wrong family
            SocksAddr::Ip(addr) if addr.is_ipv6() => {
                device.ipv6_addr().await.map(IpAddr::V6).map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale ipv6 address for ipv6 \
                         destination: {e}"
                    ))
                })?
            }
            SocksAddr::Ip(_) => {
                device.ipv4_addr().await.map(IpAddr::V4).map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale ipv4 address for ipv4 \
                         destination: {e}"
                    ))
                })?
            }
            // Domain destination: v4-first with v6 fallback is appropriate
            SocksAddr::Domain(..) => match device.ipv4_addr().await {
                Ok(ip) => IpAddr::V4(ip),
                Err(_) => device.ipv6_addr().await.map(IpAddr::V6).map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale address: {e}"
                    ))
                })?,
            },
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
        if let Some(state_dir) = &self.opts.state_dir {
            m.insert("state-dir".to_owned(), Box::new(state_dir.clone()) as _);
        }
        if let Some(hostname) = &self.opts.hostname {
            m.insert("hostname".to_owned(), Box::new(hostname.clone()) as _);
        }
        if let Some(control_url) = &self.opts.control_url {
            m.insert("control-url".to_owned(), Box::new(control_url.clone()) as _);
        }
        m.insert(
            "client-name".to_owned(),
            Box::new(
                self.opts
                    .client_name
                    .as_deref()
                    .unwrap_or(TAILSCALE_CLIENT_NAME)
                    .to_owned(),
            ) as _,
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
    use std::net::SocketAddr;

    use super::{Handler, HandlerOptions};
    use crate::proxy::{OutboundHandler, PlainProxyAPIResponse};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const DNS_TEST_TXID: u16 = 0xBEEF;

    fn env_or_default(var: &str, default: &str) -> String {
        std::env::var(var)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| default.to_owned())
    }

    fn build_dns_query(host: &str, txid: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(64);
        q.extend_from_slice(&txid.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        for label in host.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    #[tokio::test]
    async fn tailscale_support_udp_is_enabled() {
        let h = Handler::new(HandlerOptions {
            name: "ts".to_owned(),
            state_dir: None,
            auth_key: None,
            hostname: None,
            control_url: None,
            client_name: None,
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
            client_name: None,
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
    async fn tailscale_live_auth_key_supports_real_tcp_and_udp_traffic() {
        let auth_key = match std::env::var("TS_AUTH_KEY") {
            Ok(v) if !v.is_empty() => v,
            _ => return,
        };

        let udp_addr: SocketAddr =
            env_or_default("TS_TEST_UDP_ADDR", "100.100.100.100:53")
                .parse()
                .expect("TS_TEST_UDP_ADDR should be a valid socket address");
        let udp_query_name =
            env_or_default("TS_TEST_UDP_QUERY_NAME", "login.tailscale.com");

        let h = Handler::new(HandlerOptions {
            name: "ts-live-auth".to_owned(),
            state_dir: None,
            auth_key: Some(auth_key),
            hostname: None,
            control_url: None,
            client_name: None,
            ephemeral: true,
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

        // TCP: self-connection loopback via the tailscale userspace netstack.
        // A fresh ephemeral node has no exit node, so public internet IPs are
        // not routable through the tailscale stack.  Instead we listen on our
        // own tailscale IP and connect back to it — this exercises both
        // tcp_listen and tcp_connect end-to-end without needing any peers.
        let listen_port: u16 = 19988;
        let listen_addr: SocketAddr = (addr, listen_port).into();
        let listener = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            device.tcp_listen(listen_addr),
        )
        .await
        .expect("timed out creating tcp listener on tailscale")
        .expect("failed to create tcp listener on tailscale");

        let connect_addr: SocketAddr = (addr, listen_port).into();
        let device2 = Arc::clone(&device);
        let connect_task = tokio::spawn(async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(20),
                device2.tcp_connect(connect_addr),
            )
            .await
            .expect("timed out connecting tcp to self over tailscale")
            .expect("failed to connect tcp to self over tailscale")
        });

        let mut server_stream = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            listener.accept(),
        )
        .await
        .expect("timed out accepting tcp connection over tailscale")
        .expect("failed to accept tcp connection over tailscale");

        let mut client_stream =
            connect_task.await.expect("tcp connect task panicked");

        let payload = b"hello tailscale tcp";
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_stream.write_all(payload),
        )
        .await
        .expect("timed out writing tcp data over tailscale")
        .expect("failed to write tcp data over tailscale");
        client_stream.flush().await.ok();

        let mut buf = vec![0u8; payload.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            server_stream.read_exact(&mut buf),
        )
        .await
        .expect("timed out reading tcp data over tailscale")
        .expect("failed to read tcp data over tailscale");
        assert_eq!(buf, payload, "tcp data mismatch over tailscale");

        // UDP: query Tailscale MagicDNS (100.100.100.100:53) — always reachable
        // from any authenticated tailscale node without an exit node.
        let udp_socket = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            device.udp_bind((addr, 0).into()),
        )
        .await
        .expect("timed out creating udp socket over tailscale")
        .expect("failed to create udp socket over tailscale");
        let txid = DNS_TEST_TXID;
        let query = build_dns_query(&udp_query_name, txid);
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            udp_socket.send_to(udp_addr, &query),
        )
        .await
        .expect("timed out sending udp request over tailscale")
        .expect("failed to send udp request over tailscale");
        let (_, udp_resp) = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            udp_socket.recv_from_bytes(),
        )
        .await
        .expect("timed out receiving udp response over tailscale")
        .expect("failed to receive udp response over tailscale");
        assert!(
            udp_resp.len() >= 2,
            "expected non-empty udp response over tailscale"
        );
        let resp_txid = u16::from_be_bytes([udp_resp[0], udp_resp[1]]);
        assert_eq!(resp_txid, txid, "unexpected udp DNS transaction id");
    }
}
