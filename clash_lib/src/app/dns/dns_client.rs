use std::{
    fmt::{Debug, Display, Formatter},
    net,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;

use hickory_client::{
    client, client::AsyncClient, proto::iocompat::AsyncIoTokioAsStd,
    tcp::TcpClientStream, udp::UdpClientStream,
};
use hickory_proto::error::ProtoError;
use rustls::ClientConfig;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{info, warn};

use crate::{
    common::tls::{self, GLOBAL_ROOT_STORE},
    dns::{dhcp::DhcpClient, ThreadSafeDNSClient},
};
use hickory_proto::{
    h2::HttpsClientStreamBuilder,
    op::Message,
    rustls::tls_client_connect_with_bind_addr,
    xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
    DnsHandle,
};
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};

use crate::{proxy::utils::Interface, Error};

use super::{ClashResolver, Client};

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
                    write!(f, "bind: {}", iface)?;
                }
                Ok(())
            }
            DnsConfig::Tcp(addr, iface) => {
                write!(f, "TCP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {}", iface)?;
                }
                Ok(())
            }
            DnsConfig::Tls(addr, host, iface) => {
                write!(f, "TLS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {}", iface)?;
                }
                write!(f, "host: {}", host)
            }
            DnsConfig::Https(addr, host, iface) => {
                write!(f, "HTTPS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {}", iface)?;
                }
                write!(f, "host: {}", host)
            }
        }
    }
}

struct Inner {
    c: Option<client::AsyncClient>,
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
                let ip = if let Some(r) = opts.r {
                    if let Some(ip) =
                        r.resolve(&opts.host, false).await.map_err(|x| {
                            anyhow!("resolve hostname failure: {}", x.to_string())
                        })?
                    {
                        ip
                    } else {
                        return Err(Error::InvalidConfig(format!(
                            "can't resolve default DNS: {}",
                            opts.host
                        ))
                        .into());
                    }
                } else {
                    opts.host.parse::<net::IpAddr>().map_err(|x| {
                        Error::DNSError(format!(
                            "resolve DNS hostname error: {}, {}",
                            x, opts.host
                        ))
                    })?
                };

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

        if let Some(bg) = &inner.bg_handle {
            if bg.is_finished() {
                warn!(
                    "dns client background task is finished, likely connection \
                     closed, restarting a new one"
                );
                let (client, bg) = dns_stream_builder(&self.cfg).await?;
                inner.c.replace(client);
                inner.bg_handle.replace(bg);
            }
        } else {
            // initializing client
            info!("initializing dns client: {}", &self.cfg);
            let (client, bg) = dns_stream_builder(&self.cfg).await?;
            inner.c.replace(client);
            inner.bg_handle.replace(bg);
        }

        let mut req = DnsRequest::new(msg.clone(), DnsRequestOptions::default());
        req.set_id(rand::random::<u16>());

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
) -> Result<(AsyncClient, JoinHandle<Result<(), ProtoError>>), Error> {
    match cfg {
        DnsConfig::Udp(addr, iface) => {
            let stream =
                UdpClientStream::<TokioUdpSocket>::with_bind_addr_and_timeout(
                    net::SocketAddr::new(addr.ip(), addr.port()),
                    // TODO: simplify this match
                    match iface {
                        Some(Interface::IpAddr(ip)) => Some(SocketAddr::new(*ip, 0)),
                        _ => None,
                    },
                    Duration::from_secs(5),
                );
            client::AsyncClient::connect(stream)
                .await
                .map(|(x, y)| (x, tokio::spawn(y)))
                .map_err(|x| Error::DNSError(x.to_string()))
        }
        DnsConfig::Tcp(addr, iface) => {
            let (stream, sender) = TcpClientStream::<
                AsyncIoTokioAsStd<TokioTcpStream>,
            >::with_bind_addr_and_timeout(
                net::SocketAddr::new(addr.ip(), addr.port()),
                match iface {
                    Some(Interface::IpAddr(ip)) => Some(SocketAddr::new(*ip, 0)),
                    _ => None,
                },
                Duration::from_secs(5),
            );

            client::AsyncClient::new(stream, sender, None)
                .await
                .map(|(x, y)| (x, tokio::spawn(y)))
                .map_err(|x| Error::DNSError(x.to_string()))
        }
        DnsConfig::Tls(addr, host, iface) => {
            let mut tls_config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            tls_config.alpn_protocols = vec!["dot".into()];

            let (stream, sender) = tls_client_connect_with_bind_addr::<
                AsyncIoTokioAsStd<TokioTcpStream>,
            >(
                net::SocketAddr::new(addr.ip(), addr.port()),
                match iface {
                    Some(Interface::IpAddr(ip)) => Some(SocketAddr::new(*ip, 0)),
                    _ => None,
                },
                host.clone(),
                Arc::new(tls_config),
            );

            client::AsyncClient::with_timeout(
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
                .with_safe_defaults()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            tls_config.alpn_protocols = vec!["h2".into()];

            if host == &addr.ip().to_string() {
                tls_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(tls::NoHostnameTlsVerifier));
            }

            let mut stream_builder =
                HttpsClientStreamBuilder::with_client_config(Arc::new(tls_config));
            if let Some(Interface::IpAddr(ip)) = iface {
                stream_builder.bind_addr(net::SocketAddr::new(*ip, 0));
            }
            let stream = stream_builder.build::<AsyncIoTokioAsStd<TokioTcpStream>>(
                net::SocketAddr::new(addr.ip(), addr.port()),
                host.clone(),
            );

            client::AsyncClient::connect(stream)
                .await
                .map(|(x, y)| (x, tokio::spawn(y)))
                .map_err(|x| Error::DNSError(x.to_string()))
        }
    }
}
