use std::str::FromStr;
use std::{net, sync::Arc, time::Duration};

use async_trait::async_trait;
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use trust_dns_client::{
    client, proto::iocompat::AsyncIoTokioAsStd, tcp::TcpClientStream, udp::UdpClientStream,
};

use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::net::{TcpStream as TokioTcpStream, TcpStream};
use trust_dns_proto::https::{HttpsClientStream, HttpsClientStreamBuilder};
use trust_dns_proto::rustls::tls_client_connect_with_bind_addr;
use trust_dns_proto::tcp::TcpClientConnect;
use trust_dns_proto::{
    op,
    xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
    DnsHandle,
};

use crate::Error;

use super::{resolver::ClashResolver, Client};

pub struct DnsClient {
    c: client::AsyncClient,
}

#[derive(Clone, Debug)]
pub enum DNSNetMode {
    UDP,
    TCP,
    DoT,
    DoH,
}

impl FromStr for DNSNetMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UDP" => Ok(Self::UDP),
            "TCP" => Ok(Self::TCP),
            "DoH" => Ok(Self::DoH),
            "DoT" => Ok(Self::DoT),
            _ => Err(Error::DNSError("unsupported protocol".into())),
        }
    }
}

pub struct Opts {
    pub r: Option<Arc<dyn ClashResolver>>,
    pub host: String,
    pub port: u16,
    pub net: DNSNetMode,
    pub iface: Option<net::SocketAddr>,
}

impl DnsClient {
    pub async fn new(opts: Opts) -> anyhow::Result<Self> {
        let ip = if let Some(r) = opts.r {
            if let Some(ip) = r
                .resolve(&opts.host)
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

        match opts.net {
            DNSNetMode::UDP => {
                let stream = UdpClientStream::<TokioUdpSocket>::with_bind_addr_and_timeout(
                    net::SocketAddr::new(ip, opts.port),
                    opts.iface,
                    Duration::from_secs(5),
                );
                let (client, bg) = client::AsyncClient::connect(stream)
                    .await
                    .map_err(|x| Error::DNSError(x.to_string()))?;

                tokio::spawn(bg);
                Ok(Self { c: client })
            }
            DNSNetMode::TCP => {
                let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::with_bind_addr_and_timeout(
                    net::SocketAddr::new(ip, opts.port),
                    opts.iface,
                    Duration::from_secs(5),
                );

                let (client, bg) = client::AsyncClient::new(stream, sender, None)
                    .await
                    .map_err(|x| Error::DNSError(x.to_string()))?;
                tokio::spawn(bg);
                Ok(Self { c: client })
            }
            DNSNetMode::DoT => {
                let mut root_store = RootCertStore::empty();
                root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
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

                let (stream, sender) =
                    tls_client_connect_with_bind_addr::<AsyncIoTokioAsStd<TokioTcpStream>>(
                        net::SocketAddr::new(ip, opts.port),
                        opts.iface,
                        opts.host,
                        Arc::new(tls_config),
                    );

                let (client, bg) = client::AsyncClient::new(stream, sender, None)
                    .await
                    .map_err(|x| Error::DNSError(x.to_string()))?;

                tokio::spawn(bg);
                Ok(Self { c: client })
            }
            DNSNetMode::DoH => {
                let mut root_store = RootCertStore::empty();
                root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
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

                let mut stream_builder =
                    HttpsClientStreamBuilder::with_client_config(Arc::new(tls_config));
                if let Some(iface) = opts.iface {
                    stream_builder.bind_addr(iface);
                }
                let stream = stream_builder.build::<AsyncIoTokioAsStd<TokioTcpStream>>(
                    net::SocketAddr::new(ip, opts.port),
                    opts.host,
                );
                let (client, bg) = client::AsyncClient::connect(stream)
                    .await
                    .map_err(|x| Error::DNSError(x.to_string()))?;

                tokio::spawn(bg);
                Ok(Self { c: client })
            }
        }
    }
}

#[async_trait]
impl Client for DnsClient {
    async fn exchange(&mut self, msg: &op::Message) -> Result<op::Message, Error> {
        let mut req = DnsRequest::new(msg.clone(), DnsRequestOptions::default());
        req.set_id(rand::random::<u16>());
        self.c
            .send(req)
            .first_answer()
            .await
            .map(|x| x.into())
            .map_err(|e| Error::DNSError(e.to_string()))
    }
}
