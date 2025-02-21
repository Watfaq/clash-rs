use std::{
    fmt::{Debug, Display, Formatter},
    net,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;

use futures::{future::BoxFuture, TryFutureExt};
use hickory_client::client;
use hickory_proto::{
    runtime::iocompat::AsyncIoTokioAsStd,
    rustls::tls_client_stream::tls_client_connect_with_future, tcp::TcpClientStream,
    udp::UdpClientStream, ProtoError,
};
use rustls::ClientConfig;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{info, warn};

use crate::{
    common::tls::{self, GLOBAL_ROOT_STORE},
    dns::{dhcp::DhcpClient, ThreadSafeDNSClient},
    proxy::utils::new_tcp_stream,
};
use hickory_proto::{
    h2::HttpsClientStreamBuilder,
    op::Message,
    xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
    DnsHandle,
};
use tokio::net::TcpStream as TokioTcpStream;

use crate::{proxy::utils::Interface, Error};

use super::{runtime::DnsRuntimeProvider, ClashResolver, Client};

#[derive(Clone, Debug, PartialEq)]
pub enum DNSNetMode {
    Udp,
    Tcp,
    DoT,
    DoH,
    Dhcp,
}

impl Display for DNSNetMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::Tcp => write!(f, "TCP"),
            Self::DoT => write!(f, "DoT"),
            Self::DoH => write!(f, "DoH"),
            Self::Dhcp => write!(f, "DHCP"),
        }
    }
}

impl FromStr for DNSNetMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UDP" => Ok(Self::Udp),
            "TCP" => Ok(Self::Tcp),
            "DoH" => Ok(Self::DoH),
            "DoT" => Ok(Self::DoT),
            "DHCP" => Ok(Self::Dhcp),
            _ => Err(Error::DNSError("unsupported protocol".into())),
        }
    }
}

#[derive(Clone)]
pub struct Opts {
    pub r: Option<Arc<dyn ClashResolver>>,
    pub host: String,
    pub port: u16,
    pub net: DNSNetMode,
    pub iface: Option<Interface>,
}

enum DnsConfig {
    Udp(net::SocketAddr, Option<Interface>),
    Tcp(net::SocketAddr, Option<Interface>),
    Tls(net::SocketAddr, String, Option<Interface>),
    Https(net::SocketAddr, String, Option<Interface>),
}

impl Display for DnsConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            DnsConfig::Udp(addr, iface) => {
                write!(f, "UDP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {} ", iface)?;
                }
                Ok(())
            }
            DnsConfig::Tcp(addr, iface) => {
                write!(f, "TCP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {} ", iface)?;
                }
                Ok(())
            }
            DnsConfig::Tls(addr, host, iface) => {
                write!(f, "TLS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {} ", iface)?;
                }
                write!(f, "host: {}", host)
            }
            DnsConfig::Https(addr, host, iface) => {
                write!(f, "HTTPS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {} ", iface)?;
                }
                write!(f, "host: {}", host)
            }
        }
    }
}

struct Inner {
    c: Option<client::Client>,
    bg_handle: Option<JoinHandle<Result<(), ProtoError>>>,
}

/// DnsClient
pub struct DnsClient {
    inner: Arc<RwLock<Inner>>,

    cfg: DnsConfig,

    // debug purpose
    host: String,
    port: u16,
    net: DNSNetMode,
    iface: Option<Interface>,
}

impl DnsClient {
    pub async fn new_client(opts: Opts) -> anyhow::Result<ThreadSafeDNSClient> {
        // TODO: use proxy to connect?
        match &opts.net {
            DNSNetMode::Dhcp => Ok(Arc::new(DhcpClient::new(&opts.host).await)),

            other => {
                let ip = match opts.r { Some(r) => {
                    match r.resolve(&opts.host, false).await.map_err(|x| {
                            anyhow!("resolve hostname failure: {}", x.to_string())
                        })?
                    { Some(ip) => {
                        ip
                    } _ => {
                        return Err(Error::InvalidConfig(format!(
                            "can't resolve default DNS: {}",
                            opts.host
                        ))
                        .into());
                    }}
                } _ => {
                    opts.host.parse::<net::IpAddr>().map_err(|x| {
                        Error::DNSError(format!(
                            "resolve DNS hostname error: {}, {}",
                            x, opts.host
                        ))
                    })?
                }};

                match other {
                    DNSNetMode::Udp => {
                        let cfg = DnsConfig::Udp(
                            net::SocketAddr::new(ip, opts.port),
                            opts.iface.clone(),
                        );

                        Ok(Arc::new(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,

                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                        }))
                    }
                    DNSNetMode::Tcp => {
                        let cfg = DnsConfig::Tcp(
                            net::SocketAddr::new(ip, opts.port),
                            opts.iface.clone(),
                        );

                        Ok(Arc::new(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,

                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                        }))
                    }
                    DNSNetMode::DoT => {
                        let cfg = DnsConfig::Tls(
                            net::SocketAddr::new(ip, opts.port),
                            opts.host.clone(),
                            opts.iface.clone(),
                        );

                        Ok(Arc::new(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,

                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                        }))
                    }
                    DNSNetMode::DoH => {
                        let cfg = DnsConfig::Https(
                            net::SocketAddr::new(ip, opts.port),
                            opts.host.clone(),
                            opts.iface.clone(),
                        );

                        Ok(Arc::new(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,
                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                        }))
                    }
                    _ => unreachable!("."),
                }
            }
        }
    }
}

impl Debug for DnsClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("net", &self.net)
            .field("iface", &self.iface)
            .finish()
    }
}

#[async_trait]
impl Client for DnsClient {
    fn id(&self) -> String {
        format!("{}#{}:{}", &self.net, &self.host, &self.port)
    }

    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
        let mut inner = self.inner.write().await;

        match &inner.bg_handle { Some(bg) => {
            if bg.is_finished() {
                warn!(
                    "dns client background task is finished, likely connection \
                     closed, restarting a new one"
                );
                let (client, bg) = dns_stream_builder(&self.cfg).await?;
                inner.c.replace(client);
                inner.bg_handle.replace(bg);
            }
        } _ => {
            // initializing client
            info!("initializing dns client: {}", &self.cfg);
            let (client, bg) = dns_stream_builder(&self.cfg).await?;
            inner.c.replace(client);
            inner.bg_handle.replace(bg);
        }}

        let mut req = DnsRequest::new(msg.clone(), DnsRequestOptions::default());
        if req.id() == 0 {
            req.set_id(rand::random::<u16>());
        }
        inner
            .c
            .as_ref()
            .unwrap()
            .send(req)
            .first_answer()
            .await
            .map_err(|x| Error::DNSError(x.to_string()).into())
            .map(|x| x.into())
    }
}

async fn dns_stream_builder(
    cfg: &DnsConfig,
) -> Result<(client::Client, JoinHandle<Result<(), ProtoError>>), Error> {
    match cfg {
        DnsConfig::Udp(addr, iface) => {
            let stream = UdpClientStream::builder(
                *addr,
                DnsRuntimeProvider::new(iface.clone()),
            )
            .with_timeout(Some(Duration::from_secs(5)))
            .build();

            client::Client::connect(stream)
                .await
                .map(|(x, y)| (x, tokio::spawn(y)))
                .map_err(|x| Error::DNSError(x.to_string()))
        }
        DnsConfig::Tcp(addr, iface) => {
            let (stream, sender) = TcpClientStream::new(
                *addr,
                None,
                Some(Duration::from_secs(5)),
                DnsRuntimeProvider::new(iface.clone()),
            );

            client::Client::new(stream, sender, None)
                .await
                .map(|(x, y)| (x, tokio::spawn(y)))
                .map_err(|x| Error::DNSError(x.to_string()))
        }
        DnsConfig::Tls(addr, host, iface) => {
            let mut tls_config = ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            tls_config.alpn_protocols = vec!["dot".into(), "h2".into()];

            let fut = new_tcp_stream(
                *addr,
                iface.clone(),
                #[cfg(target_os = "linux")]
                None,
            )
            .map_ok(AsyncIoTokioAsStd);

            let (stream, sender) = tls_client_connect_with_future::<
                AsyncIoTokioAsStd<TokioTcpStream>,
                BoxFuture<
                    'static,
                    std::io::Result<AsyncIoTokioAsStd<TokioTcpStream>>,
                >,
            >(
                Box::pin(fut),
                net::SocketAddr::new(addr.ip(), addr.port()),
                host.clone(),
                Arc::new(tls_config),
            );

            client::Client::with_timeout(
                stream,
                sender,
                Duration::from_secs(5),
                None,
            )
            .await
            .map(|(x, y)| (x, tokio::spawn(y)))
            .map_err(|x| Error::DNSError(x.to_string()))
        }
        DnsConfig::Https(addr, host, iface) => {
            let mut tls_config = ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            tls_config.alpn_protocols = vec!["h2".into()];

            if host == &addr.ip().to_string() {
                tls_config.dangerous().set_certificate_verifier(Arc::new(
                    tls::NoHostnameTlsVerifier::new(),
                ));
            }

            let stream = HttpsClientStreamBuilder::with_client_config(
                Arc::new(tls_config),
                DnsRuntimeProvider::new(iface.clone()),
            )
            .build(*addr, host.to_owned(), "/dns-query".to_string());

            client::Client::connect(stream)
                .await
                .map(|(x, y)| (x, tokio::spawn(y)))
                .map_err(|x| Error::DNSError(x.to_string()))
        }
    }
}
