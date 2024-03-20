mod handle_stream;
mod handle_task;
mod types;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use axum::async_trait;
use quinn::{EndpointConfig, TokioRuntime};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use uuid::Uuid;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::tls::GLOBAL_ROOT_STORE,
    proxy::tuic::types::{ServerAddr, TuicEndpoint},
    session::{Session, SocksAddr},
};

use quinn::ClientConfig as QuinnConfig;
use quinn::Endpoint as QuinnEndpoint;
use quinn::TransportConfig as QuinnTransportConfig;
use quinn::{congestion::CubicConfig, VarInt};
use tokio::sync::Mutex as AsyncMutex;

use rustls::client::ClientConfig as TlsConfig;

use self::types::TuicConnection;

use super::{AnyOutboundHandler, AnyStream, OutboundHandler, OutboundType};

#[derive(Debug, Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub udp_relay_mode: String,
    pub disable_sni: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    ep: TuicEndpoint,
    conn: AsyncMutex<Option<TuicConnection>>,
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tuic
    }

    async fn remote_addr(&self) -> Option<SocksAddr> {
        None
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn proxy_stream(
        &self,
        s: AnyStream,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        tracing::warn!("Proxy stream currently is direcrt connect");
        Ok(s)
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        self.do_connect_stream(sess, resolver).await.map_err(|e| {
            tracing::error!("[tuic] {:?}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        self.do_connect_datagram(sess, resolver).await.map_err(|e| {
            tracing::error!("[tuic] {:?}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> anyhow::Result<AnyOutboundHandler> {
        let mut crypto = TlsConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        // aborted by peer: the cryptographic handshake failed: error 120: peer doesn't support any known protocol
        crypto.alpn_protocols = vec!["h3".to_string()]
            .into_iter()
            .map(|alpn| alpn.into_bytes())
            .collect();
        crypto.enable_early_data = true;
        crypto.enable_sni = !opts.disable_sni;
        let mut quinn_config = QuinnConfig::new(Arc::new(crypto));
        let mut quinn_transport_config = QuinnTransportConfig::default();
        quinn_transport_config
            .max_concurrent_bidi_streams(VarInt::from_u32(32))
            .max_concurrent_uni_streams(VarInt::from_u32(32))
            .send_window(16777216)
            .stream_receive_window(VarInt::from_u32(8388608))
            .max_idle_timeout(None)
            .congestion_controller_factory(Arc::new(CubicConfig::default()));
        quinn_config.transport_config(Arc::new(quinn_transport_config));
        // Try to create an IPv4 socket as the placeholder first, if it fails, try IPv6.
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .or_else(|err| {
                UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).map_err(|_| err)
            })
            .map_err(|err| anyhow!("failed to create endpoint UDP socket {}", err))?;

        let mut endpoint = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )?;
        endpoint.set_default_client_config(quinn_config);
        let endpoint = TuicEndpoint {
            ep: endpoint,
            server: ServerAddr::new(opts.server.clone(), opts.port, None),
            uuid: opts.uuid,
            password: Arc::from(opts.password.clone().into_bytes().into_boxed_slice()),
            udp_relay_mode: types::UdpRelayMode::Native,
            zero_rtt_handshake: false,
            heartbeat: Duration::from_secs(3),
            gc_interval: Duration::from_secs(3),
            gc_lifetime: Duration::from_secs(15),
        };
        Ok(Arc::new(Handler {
            opts,
            ep: endpoint,
            conn: AsyncMutex::new(None),
        }))
    }
    async fn get_conn(&self) -> Result<TuicConnection> {
        let fut = async {
            let mut guard = self.conn.lock().await;
            if guard.is_none() {
                // init
                *guard = Some(self.ep.connect().await?);
            }
            let conn = guard.take().unwrap();
            let conn = if conn.is_closed() {
                // reconnect
                self.ep.connect().await?
            } else {
                conn
            };
            // TODO TuicConnection is huge, is it necessary to clone it?
            *guard = Some(conn.clone());
            Ok(conn)
        };
        tokio::time::timeout(Duration::from_secs(3), fut).await?
    }

    async fn do_connect_stream(
        &self,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedChainedStream> {
        let conn = self.get_conn().await?;
        let dest = match sess.destination.clone() {
            SocksAddr::Ip(addr) => tuic::Address::SocketAddress(addr),
            SocksAddr::Domain(domain, port) => tuic::Address::DomainAddress(domain, port),
        };
        let relay = conn.connect(dest).await?.compat();

        let s = ChainedStreamWrapper::new(relay);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn do_connect_datagram(
        &self,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        todo!()
    }
}
