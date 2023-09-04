use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddr;
use std::str::FromStr;
use std::{net, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::lock::Mutex;
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use trust_dns_client::{
    client, proto::iocompat::AsyncIoTokioAsStd, tcp::TcpClientStream, udp::UdpClientStream,
};

use crate::common::tls;
use crate::dns::dhcp::DhcpClient;
use crate::dns::ThreadSafeDNSClient;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket as TokioUdpSocket;
use trust_dns_proto::https::HttpsClientStreamBuilder;
use trust_dns_proto::op::Message;
use trust_dns_proto::rustls::tls_client_connect_with_bind_addr;
use trust_dns_proto::{
    xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
    DnsHandle,
};

use crate::proxy::utils::Interface;
use crate::Error;

use super::{ClashResolver, Client};

#[derive(Clone, Debug, PartialEq)]
pub enum DNSNetMode {
    UDP,
    TCP,
    DoT,
    DoH,
    DHCP,
}

impl Display for DNSNetMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UDP => write!(f, "UDP"),
            Self::TCP => write!(f, "TCP"),
            Self::DoT => write!(f, "DoT"),
            Self::DoH => write!(f, "DoH"),
            Self::DHCP => write!(f, "DHCP"),
        }
    }
}

impl FromStr for DNSNetMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UDP" => Ok(Self::UDP),
            "TCP" => Ok(Self::TCP),
            "DoH" => Ok(Self::DoH),
            "DoT" => Ok(Self::DoT),
            "DHCP" => Ok(Self::DHCP),
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

/// DnsClient
pub struct DnsClient {
    c: client::AsyncClient,

    // debug purpose
    host: String,
    port: u16,
    net: DNSNetMode,
    iface: Option<Interface>,
}

impl DnsClient {
    pub async fn new(opts: Opts) -> anyhow::Result<ThreadSafeDNSClient> {
        // TODO: use proxy to connect?
        match &opts.net {
            DNSNetMode::DHCP => Ok(Arc::new(Mutex::new(DhcpClient::new(&opts.host).await))),

            other => {
                let ip = if let Some(r) = opts.r {
                    if let Some(ip) = r
                        .resolve(&opts.host, false)
                        .await
                        .map_err(|x| anyhow!("resolve hostname failure: {}", x.to_string()))?
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
                            x.to_string(),
                            opts.host
                        ))
                    })?
                };

                match other {
                    DNSNetMode::UDP => {
                        let stream = UdpClientStream::<TokioUdpSocket>::with_bind_addr_and_timeout(
                            net::SocketAddr::new(ip, opts.port),
                            // TODO: simplify this match
                            match &opts.iface {
                                Some(iface) => match iface {
                                    Interface::IpAddr(ip) => Some(SocketAddr::new(ip.clone(), 0)),
                                    _ => None,
                                },
                                _ => None,
                            },
                            Duration::from_secs(5),
                        );
                        let (client, bg) = client::AsyncClient::connect(stream)
                            .await
                            .map_err(|x| Error::DNSError(x.to_string()))?;

                        tokio::spawn(bg);
                        Ok(Arc::new(Mutex::new(Self {
                            c: client,

                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                        })))
                    }
                    DNSNetMode::TCP => {
                        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::with_bind_addr_and_timeout(
                            net::SocketAddr::new(ip, opts.port),
                            match &opts.iface {
                                Some(iface) => match iface {
                                    Interface::IpAddr(ip) => Some(SocketAddr::new(ip.clone(), 0)),
                                    _ => None,
                                },
                                _ => None,
                            },
                            Duration::from_secs(5),
                        );

                        let (client, bg) = client::AsyncClient::new(stream, sender, None)
                            .await
                            .map_err(|x| Error::DNSError(x.to_string()))?;
                        tokio::spawn(bg);
                        Ok(Arc::new(Mutex::new(Self {
                            c: client,
                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                        })))
                    }
                    DNSNetMode::DoT => {
                        let mut root_store = RootCertStore::empty();
                        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(
                            |ta| {
                                OwnedTrustAnchor::from_subject_spki_name_constraints(
                                    ta.subject,
                                    ta.spki,
                                    ta.name_constraints,
                                )
                            },
                        ));
                        let mut tls_config = ClientConfig::builder()
                            .with_safe_defaults()
                            .with_root_certificates(root_store)
                            .with_no_client_auth();
                        tls_config.alpn_protocols = vec!["dot".into()];

                        let (stream, sender) = tls_client_connect_with_bind_addr::<
                            AsyncIoTokioAsStd<TokioTcpStream>,
                        >(
                            net::SocketAddr::new(ip, opts.port),
                            match &opts.iface {
                                Some(iface) => match iface {
                                    Interface::IpAddr(ip) => Some(SocketAddr::new(ip.clone(), 0)),
                                    _ => None,
                                },
                                _ => None,
                            },
                            opts.host.clone(),
                            Arc::new(tls_config),
                        );

                        let (client, bg) = client::AsyncClient::with_timeout(
                            stream,
                            sender,
                            Duration::from_secs(5),
                            None,
                        )
                        .await
                        .map_err(|x| Error::DNSError(x.to_string()))?;

                        tokio::spawn(bg);
                        Ok(Arc::new(Mutex::new(Self {
                            c: client,

                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                        })))
                    }
                    DNSNetMode::DoH => {
                        let mut root_store = RootCertStore::empty();
                        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(
                            |ta| {
                                OwnedTrustAnchor::from_subject_spki_name_constraints(
                                    ta.subject,
                                    ta.spki,
                                    ta.name_constraints,
                                )
                            },
                        ));
                        let mut tls_config = ClientConfig::builder()
                            .with_safe_defaults()
                            .with_root_certificates(root_store)
                            .with_no_client_auth();
                        tls_config.alpn_protocols = vec!["h2".into()];

                        if opts.host == ip.to_string() {
                            tls_config
                                .dangerous()
                                .set_certificate_verifier(Arc::new(tls::NoHostnameTlsVerifier));
                        }

                        let mut stream_builder =
                            HttpsClientStreamBuilder::with_client_config(Arc::new(tls_config));
                        if let Some(iface) = &opts.iface {
                            match iface {
                                Interface::IpAddr(ip) => {
                                    stream_builder.bind_addr(net::SocketAddr::new(ip.clone(), 0))
                                }
                                _ => {}
                            }
                        }
                        let stream = stream_builder.build::<AsyncIoTokioAsStd<TokioTcpStream>>(
                            net::SocketAddr::new(ip, opts.port),
                            opts.host.clone(),
                        );

                        let (client, bg) = client::AsyncClient::connect(stream)
                            .await
                            .map_err(|x| Error::DNSError(x.to_string()))?;

                        tokio::spawn(bg);
                        Ok(Arc::new(Mutex::new(Self {
                            c: client,
                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                        })))
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
    async fn exchange(&mut self, msg: &Message) -> anyhow::Result<Message> {
        let mut req = DnsRequest::new(msg.clone(), DnsRequestOptions::default());
        req.set_id(rand::random::<u16>());
        self.c
            .send(req)
            .first_answer()
            .await
            .map_err(|x| Error::DNSError(x.to_string()).into())
            .map(|x| x.into())
    }
}
