use std::{
    fmt::{Debug, Formatter},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    pin::Pin,
    str::FromStr,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};
mod codec;
mod congestion;
mod salamander;
mod udp_hop;

use anyhow::Context as _;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::{
    crypto::rustls::QuicClientConfig, AsyncUdpSocket, ClientConfig, Connection,
    Runtime, TokioRuntime,
};
use quinn_proto::TransportConfig;

use rustls::{
    client::{
        danger::{ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::CertificateDer,
    ClientConfig as RustlsClientConfig,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    select,
    sync::{Mutex, OnceCell},
};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::{
        errors::new_io_error,
        tls::GLOBAL_ROOT_STORE,
        utils::{encode_hex, sha256},
    },
    // proxy::hysteria2::congestion::DynCongestion,
    session::{Session, SocksAddr},
};
use tracing::{debug, trace};

use self::{
    codec::Hy2TcpCodec,
    congestion::{Burtal, DynController},
};

use super::{
    converters::hysteria2::PortGenrateor, utils::new_udp_socket, ConnectorType,
    DialWithConnector, OutboundHandler, OutboundType,
};

pub use salamander::SalamanderObfs;

#[derive(Clone)]
pub enum Obfs {
    Salamander(salamander::SalamanderObfs),
}

#[derive(Clone)]
pub struct HystOption {
    pub name: String,
    pub addr: SocksAddr,
    pub ports: Option<PortGenrateor>,
    pub sni: Option<String>,
    pub passwd: String,
    pub obfs: Option<Obfs>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    #[allow(dead_code)]
    pub up_down: Option<(u64, u64)>,
    pub fingerprint: Option<[u8; 32]>,
    pub ca: Option<CertificateDer<'static>>,
    #[allow(dead_code)]
    pub cwnd: Option<u64>,
}

impl HystOption {
    async fn get_udp_socket(
        &self,
        sess: &crate::session::Session,
        is_ipv6: bool,
    ) -> std::io::Result<Arc<dyn AsyncUdpSocket>> {
        let socket_addr = if is_ipv6 {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        };
        let udp_socket = new_udp_socket(
            socket_addr.into(),
            sess.iface.clone(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            sess.so_mark,
        )
        .await
        .unwrap();
        let udp_socket = udp_socket.into_std()?;

        let udp = if let Some(obfs) = &self.obfs {
            match obfs {
                Obfs::Salamander(key) => {
                    Arc::new(salamander::Salamander::new(udp_socket, key.clone())?)
                }
            }
        } else {
            TokioRuntime.wrap_udp_socket(udp_socket)?
        };

        if let Some(ports) = &self.ports {
            let server_port = ports.get();
            Ok(Arc::new(udp_hop::Hop::new(
                udp,
                server_port,
                self.addr.port(),
            )))
        } else {
            Ok(udp)
        }
    }
}
#[derive(Debug)]
struct CertVerifyOption {
    fingerprint: Option<[u8; 32]>,
    certificate: Option<CertificateDer<'static>>,
    skip: bool,
    pki: Arc<WebPkiServerVerifier>,
}

impl CertVerifyOption {
    fn new(
        fingerprint: Option<[u8; 32]>,
        certificate: Option<CertificateDer<'static>>,
        skip: bool,
    ) -> Self {
        Self {
            certificate,
            fingerprint,
            skip,
            pki: WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
                .build()
                .unwrap(),
        }
    }
}

impl ServerCertVerifier for CertVerifyOption {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(ref fingerprint) = self.fingerprint {
            let cert_sha256 = sha256(end_entity.as_ref());
            assert!(cert_sha256.len() == 32);
            let cert_sha256: [u8; 32] = cert_sha256.try_into().unwrap();

            if &cert_sha256 != fingerprint {
                return Err(rustls::Error::General(format!(
                    "cert hash mismatch: found: {}\nexpect: {}",
                    encode_hex(&cert_sha256),
                    encode_hex(fingerprint)
                )));
            } else {
                return Ok(ServerCertVerified::assertion());
            }
        }

        if let Some(ref cert) = self.certificate {
            if cert != end_entity {
                return Err(rustls::Error::General(format!("cert mismatch",)));
            } else {
                return Ok(ServerCertVerified::assertion());
            }
        }

        if self.skip {
            return Ok(ServerCertVerified::assertion());
        }
        self.pki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.pki.supported_verify_schemes()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if self.skip {
            return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
        }
        self.pki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if self.skip {
            return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
        }
        self.pki.verify_tls13_signature(message, cert, dss)
    }
}

enum CcRx {
    Auto,
    Fixed(#[allow(dead_code)] u64),
}

impl FromStr for CcRx {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("auto") {
            Ok(Self::Auto)
        } else {
            let n = s.parse::<u64>()?;
            Ok(Self::Fixed(n))
        }
    }
}

pub struct Handler {
    opts: HystOption,
    ep: OnceCell<quinn::Endpoint>,
    client_config: quinn::ClientConfig,
    session: Mutex<Option<Arc<quinn::Connection>>>,
    // a send request guard to keep the connection alive
    guard: Mutex<Option<SendRequest<OpenStreams, Bytes>>>,
    // support udp is decided by server
    support_udp: RwLock<bool>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystClient").finish()
    }
}

impl Handler {
    const DEFAULT_MAX_IDLE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(300);
    const HOP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

    pub fn new(opts: HystOption) -> anyhow::Result<Self> {
        let verify = CertVerifyOption::new(
            opts.fingerprint,
            opts.ca.clone(),
            opts.skip_cert_verify,
        );
        // let verify = DummyTlsVerifier::new();
        let mut tls_config = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verify))
            .with_no_client_auth();

        // should set alpn_protocol `h3` default
        tls_config.alpn_protocols = if opts.alpn.is_empty() {
            vec![b"h3".to_vec()]
        } else {
            opts.alpn.iter().map(|x| x.as_bytes().to_vec()).collect()
        };

        let mut transport = TransportConfig::default();
        // TODO
        // transport.congestion_controller_factory(DynCongestion);
        transport.max_idle_timeout(Some(
            Self::DEFAULT_MAX_IDLE_TIMEOUT.try_into().unwrap(),
        ));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

        let quic_config: QuicClientConfig = tls_config.try_into().unwrap();
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));

        Ok(Self {
            opts,
            ep: OnceCell::new(),
            client_config,
            session: Mutex::new(None),
            guard: Mutex::new(None),
            support_udp: RwLock::new(true),
        })
    }

    async fn new_authed_session(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> anyhow::Result<(Connection, SendRequest<OpenStreams, Bytes>)> {
        // Everytime we enstablish a new session, we should lookup the server
        // address. maybe it changed since it use ddns
        let server_socket_addr = match self.opts.addr.clone() {
            SocksAddr::Ip(ip) => ip,
            SocksAddr::Domain(d, port) => {
                let ip = resolver
                    .resolve(d.as_str(), true)
                    .await?
                    .context(format!("resolve domain {} failed", d))?;
                SocketAddr::new(ip, port)
            }
        };

        let connection = self
            .ep
            .get_or_init(|| {
                let client_config = self.client_config.clone();
                let is_ipv6 = resolver.ipv6();
                async move {
                    let mut ep = quinn::Endpoint::new_with_abstract_socket(
                        Default::default(),
                        None,
                        self.opts.get_udp_socket(sess, is_ipv6).await.unwrap(),
                        Arc::new(TokioRuntime),
                    )
                    .unwrap();
                    ep.set_default_client_config(client_config);
                    ep
                }
            })
            .await
            .connect(server_socket_addr, self.opts.sni.as_deref().unwrap_or(""))?
            .await?;
        let (guard, _rx, udp) = Self::auth(&connection, &self.opts.passwd).await?;
        *self.support_udp.write().unwrap() = udp;
        // todo set congestion controller according to cc_rx

        match connection
            .congestion_state()
            .into_any()
            .downcast::<DynController>()
        {
            Ok(any) => {
                any.set_controller(Box::new(Burtal::new(0, connection.clone())));
            }
            Err(_) => {
                trace!("congestion controller is not set");
            }
        }

        // if the server support hop, we should rebind the udp socket
        if self.opts.ports.is_some() {
            tokio::spawn({
                let sess = sess.clone();
                let connection = connection.clone();
                let opts = self.opts.clone();
                let ep = self.ep.clone();
                async move {
                    let mut ticker = tokio::time::interval(Self::HOP_INTERVAL);
                    // ticks immediately
                    ticker.tick().await;
                    loop {
                        select! {
                            _ = ticker.tick() => {
                                let ep = ep.get().unwrap();
                                let udp = opts.get_udp_socket(&sess, ep.local_addr().unwrap().is_ipv6()).await?;
                                ep.rebind_abstract(udp)?;
                            },
                            reason = connection.closed() => {
                                tracing::debug!("hysteria session closed: {:?}", reason);
                                break;
                            },
                        }
                    }
                    Ok::<(), std::io::Error>(())
                }
            });
        }
        anyhow::Ok((connection, guard))
    }

    async fn auth(
        conn: &quinn::Connection,
        passwd: &str,
    ) -> anyhow::Result<(SendRequest<OpenStreams, Bytes>, CcRx, bool)> {
        let h3_conn = h3_quinn::Connection::new(conn.clone());

        let (_, mut sender) =
            h3::client::builder().build::<_, _, Bytes>(h3_conn).await?;

        let req = http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", passwd)
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", codec::padding(64..=512))
            .body(())?;
        let mut r = sender.send_request(req).await?;
        r.finish().await?;

        let r = r.recv_response().await?;

        const HYSTERIA_STATUS_OK: u16 = 233;
        if r.status() != HYSTERIA_STATUS_OK {
            return Err(anyhow!("auth failed: response status code {}", r.status()));
        }

        // MUST have Hysteria-CC-RX and Hysteria-UDP headers according to hysteria2
        // document
        let cc_rx = r
            .headers()
            .get("Hysteria-CC-RX")
            .context("auth failed: missing Hysteria-CC-RX header")?
            .to_str()?
            .parse()?;

        let support_udp = r
            .headers()
            .get("Hysteria-UDP")
            .context("auth failed: missing Hysteria-UDP header")?
            .to_str()?
            .parse()?;

        Ok((sender, cc_rx, support_udp))
    }
}

impl DialWithConnector for Handler {}

#[async_trait::async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Hysteria2
    }

    async fn support_udp(&self) -> bool {
        *self.support_udp.read().unwrap()
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        Err(new_io_error("hysteria2 udp is not implemented yet"))
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let authed_conn = {
            let mut session_lock = self.session.lock().await;

            match session_lock.as_ref().filter(|s| match s.close_reason() {
                // rust should have inspect method on Option and Result!
                Some(reason) => {
                    tracing::debug!("old connection closed: {:?}", reason);
                    false
                }
                None => true,
            }) {
                Some(s) => s.to_owned(),
                None => {
                    let (session, guard) = self
                        .new_authed_session(sess, resolver)
                        .await
                        .map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!(
                                    "connect to {} failed: {}",
                                    self.opts.addr, e
                                ),
                            )
                        })?;
                    let session = Arc::new(session);
                    *session_lock = Some(session.clone());
                    *self.guard.lock().await = Some(guard);
                    session
                }
            }
        };

        let (mut tx, mut rx) = authed_conn.open_bi().await?;

        tokio_util::codec::FramedWrite::new(&mut tx, Hy2TcpCodec)
            .send(&sess.destination)
            .await?;

        match tokio_util::codec::FramedRead::new(&mut rx, Hy2TcpCodec)
            .next()
            .await
        {
            Some(Ok(resp)) => {
                if resp.status != 0x00 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "server response error: addr: {}, msg: {:?}",
                            self.opts.addr, resp.msg
                        ),
                    ));
                } else {
                    debug!(
                        "hysteria2 tcp request success: status: {}, msg: {:?}",
                        resp.status, resp.msg
                    );
                }
            }
            _ => {
                return Err(std::io::Error::other(format!(
                    "not receive hysteria2 response from server: {}",
                    self.opts.addr
                )));
            }
        };

        let hyster_stream = HystStream { send: tx, recv: rx };
        Ok(Box::new(ChainedStreamWrapper::new(Box::new(hyster_stream))))
    }
}

pub struct HystStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Debug for HystStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystStream").finish()
    }
}

impl AsyncRead for HystStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for HystStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map_err(|e| {
                tracing::error!("hysteria2 write error: {}", e);
                e.into()
            })
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}
