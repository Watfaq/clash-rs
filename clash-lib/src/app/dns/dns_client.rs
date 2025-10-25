use super::{ClashResolver, Client, EdnsClientSubnet, runtime::DnsRuntimeProvider};
use std::{
    fmt::{Debug, Display, Formatter},
    net,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;

use hickory_client::client;
use hickory_proto::{
    ProtoError,
    rr::{
        RecordType,
        rdata::opt::{ClientSubnet, EdnsCode, EdnsOption},
    },
    rustls::tls_client_connect,
    tcp::TcpClientStream,
    udp::UdpClientStream,
};
use rustls::ClientConfig;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{info, instrument, trace, warn};

use crate::{
    Error,
    app::{
        dns::{self},
        net::{OutboundInterface, TUN_SOMARK},
    },
    common::tls::{self, GLOBAL_ROOT_STORE},
    dns::{ThreadSafeDNSClient, dhcp::DhcpClient},
    proxy::OutboundHandler,
};
use anyhow::anyhow;
use hickory_proto::{
    DnsHandle,
    h2::HttpsClientStreamBuilder,
    op::Message,
    xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy;
    use hickory_proto::{
        op,
        rr::{Name, rdata::opt::EdnsOption},
    };
    use std::str::FromStr;

    fn client_with_ecs(ecs: Option<EdnsClientSubnet>) -> DnsClient {
        let proxy = Arc::new(proxy::direct::Handler::new("test-proxy"));
        let addr = net::SocketAddr::new(net::IpAddr::from([127, 0, 0, 1]), 53);
        DnsClient {
            inner: Arc::new(RwLock::new(Inner {
                c: None,
                bg_handle: None,
            })),
            cfg: DnsConfig::Udp(addr, None, proxy.clone()),
            proxy,
            host: "example.org".to_string(),
            port: 53,
            net: DNSNetMode::Udp,
            iface: None,
            ecs,
        }
    }

    fn build_message(record_type: RecordType) -> Message {
        let mut msg = Message::new();
        let mut query = op::Query::new();
        query.set_name(Name::from_ascii("example.org").expect("valid name"));
        query.set_query_type(record_type);
        msg.add_query(query);
        msg
    }

    #[test]
    fn apply_edns_client_subnet_adds_ipv4_option() {
        let ecs = EdnsClientSubnet {
            ipv4: Some("1.2.3.4/24".parse().unwrap()),
            ipv6: None,
        };
        let client = client_with_ecs(Some(ecs));
        let mut msg = build_message(RecordType::A);

        client.apply_edns_client_subnet(&mut msg);

        let edns = msg.extensions().as_ref().expect("edns should exist");
        let option = edns
            .option(EdnsCode::Subnet)
            .expect("subnet option missing");
        match option {
            EdnsOption::Subnet(subnet) => {
                assert_eq!(subnet.addr(), net::IpAddr::from([1, 2, 3, 0]));
                assert_eq!(subnet.source_prefix(), 24);
                assert_eq!(subnet.scope_prefix(), 24);
            }
            _ => panic!("unexpected edns option"),
        }
    }

    #[test]
    fn apply_edns_client_subnet_prefers_ipv6_for_aaaa() {
        let ecs = EdnsClientSubnet {
            ipv4: Some("1.2.3.4/24".parse().unwrap()),
            ipv6: Some("2001:db8::/48".parse().unwrap()),
        };
        let client = client_with_ecs(Some(ecs));
        let mut msg = build_message(RecordType::AAAA);

        client.apply_edns_client_subnet(&mut msg);

        let edns = msg.extensions().as_ref().expect("edns should exist");
        let option = edns
            .option(EdnsCode::Subnet)
            .expect("subnet option missing");
        match option {
            EdnsOption::Subnet(subnet) => {
                assert_eq!(
                    subnet.addr(),
                    net::IpAddr::from_str("2001:db8::").unwrap()
                );
                assert_eq!(subnet.source_prefix(), 48);
                assert_eq!(subnet.scope_prefix(), 48);
            }
            _ => panic!("unexpected edns option"),
        }
    }

    #[test]
    fn apply_edns_client_subnet_respects_existing_option() {
        let ecs = EdnsClientSubnet {
            ipv4: Some("1.2.3.4/24".parse().unwrap()),
            ipv6: None,
        };
        let client = client_with_ecs(Some(ecs));
        let mut msg = build_message(RecordType::A);

        let mut edns = hickory_proto::op::Edns::new();
        {
            let opts = edns.options_mut();
            opts.insert(EdnsOption::Subnet(ClientSubnet::new(
                net::IpAddr::from([9, 8, 7, 0]),
                24,
                24,
            )));
        }
        msg.set_edns(edns);

        client.apply_edns_client_subnet(&mut msg);

        let edns = msg.extensions().as_ref().expect("edns should remain");
        let option = edns
            .option(EdnsCode::Subnet)
            .expect("subnet option missing");
        match option {
            EdnsOption::Subnet(subnet) => {
                assert_eq!(subnet.addr(), net::IpAddr::from([9, 8, 7, 0]));
                assert_eq!(subnet.source_prefix(), 24);
                assert_eq!(subnet.scope_prefix(), 24);
            }
            _ => panic!("unexpected edns option"),
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
    pub iface: Option<OutboundInterface>,
    pub proxy: Arc<dyn OutboundHandler>,
    pub ecs: Option<EdnsClientSubnet>,
}

enum DnsConfig {
    Udp(
        net::SocketAddr,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
    ),
    Tcp(
        net::SocketAddr,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
    ),
    Tls(
        net::SocketAddr,
        String,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
    ),
    Https(
        net::SocketAddr,
        String,
        Option<OutboundInterface>,
        Arc<dyn OutboundHandler>,
    ),
}

impl Display for DnsConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            DnsConfig::Udp(addr, iface, proxy) => {
                write!(f, "UDP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "via proxy: {}", proxy.name())?;
                Ok(())
            }
            DnsConfig::Tcp(addr, iface, proxy) => {
                write!(f, "TCP: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "via proxy: {}", proxy.name())?;
                Ok(())
            }
            DnsConfig::Tls(addr, host, iface, proxy) => {
                write!(f, "TLS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "host: {host}")?;
                write!(f, "via proxy: {}", proxy.name())
            }
            DnsConfig::Https(addr, host, iface, proxy) => {
                write!(f, "HTTPS: {}:{} ", addr.ip(), addr.port())?;
                if let Some(iface) = iface {
                    write!(f, "bind: {iface} ")?;
                }
                write!(f, "host: {host}")?;
                write!(f, "via proxy: {}", proxy.name())
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
    proxy: Arc<dyn OutboundHandler>,

    // debug purpose
    host: String,
    port: u16,
    net: DNSNetMode,
    iface: Option<OutboundInterface>,
    ecs: Option<EdnsClientSubnet>,
}

impl DnsClient {
    pub async fn new_client(opts: Opts) -> anyhow::Result<ThreadSafeDNSClient> {
        // TODO: use proxy to connect?
        match &opts.net {
            DNSNetMode::Dhcp => Ok(Arc::new(DhcpClient::new(&opts.host).await)),

            other => {
                let ip = match opts.r {
                    Some(r) => {
                        match r.resolve(&opts.host, false).await.map_err(|x| {
                            anyhow!("resolve hostname failure: {}", x)
                        })? {
                            Some(ip) => ip,
                            _ => {
                                return Err(Error::InvalidConfig(format!(
                                    "can't resolve default DNS: {}",
                                    opts.host
                                ))
                                .into());
                            }
                        }
                    }
                    _ => opts.host.parse::<net::IpAddr>().map_err(|x| {
                        Error::DNSError(format!(
                            "resolve DNS hostname error: {}, {}",
                            x, opts.host
                        ))
                    })?,
                };

                match other {
                    DNSNetMode::Udp => {
                        let cfg = DnsConfig::Udp(
                            net::SocketAddr::new(ip, opts.port),
                            opts.iface.clone(),
                            opts.proxy.clone(),
                        );

                        Ok(Arc::new(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,
                            proxy: opts.proxy,

                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                            ecs: opts.ecs.clone(),
                        }))
                    }
                    DNSNetMode::Tcp => {
                        let cfg = DnsConfig::Tcp(
                            net::SocketAddr::new(ip, opts.port),
                            opts.iface.clone(),
                            opts.proxy.clone(),
                        );

                        Ok(Arc::new(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,
                            proxy: opts.proxy,
                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                            ecs: opts.ecs.clone(),
                        }))
                    }
                    DNSNetMode::DoT => {
                        let cfg = DnsConfig::Tls(
                            net::SocketAddr::new(ip, opts.port),
                            opts.host.clone(),
                            opts.iface.clone(),
                            opts.proxy.clone(),
                        );

                        Ok(Arc::new(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,
                            proxy: opts.proxy,
                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                            ecs: opts.ecs.clone(),
                        }))
                    }
                    DNSNetMode::DoH => {
                        let cfg = DnsConfig::Https(
                            net::SocketAddr::new(ip, opts.port),
                            opts.host.clone(),
                            opts.iface.clone(),
                            opts.proxy.clone(),
                        );

                        Ok(Arc::new(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,
                            proxy: opts.proxy,
                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                            iface: opts.iface,
                            ecs: opts.ecs.clone(),
                        }))
                    }
                    _ => unreachable!("."),
                }
            }
        }
    }

    fn apply_edns_client_subnet(&self, message: &mut Message) {
        let Some(ecs) = &self.ecs else {
            return;
        };

        if ecs.ipv4.is_none() && ecs.ipv6.is_none() {
            return;
        }

        if message
            .extensions()
            .as_ref()
            .is_some_and(|edns| edns.option(EdnsCode::Subnet).is_some())
        {
            return;
        }

        let prefer_ipv6 = matches!(
            message.query().map(|q| q.query_type()),
            Some(RecordType::AAAA)
        );

        let candidate = if prefer_ipv6 {
            ecs.ipv6
                .map(|ipv6| (net::IpAddr::from(ipv6.network()), ipv6.prefix_len()))
                .or_else(|| {
                    ecs.ipv4.map(|ipv4| {
                        (net::IpAddr::from(ipv4.network()), ipv4.prefix_len())
                    })
                })
        } else {
            ecs.ipv4
                .map(|ipv4| (net::IpAddr::from(ipv4.network()), ipv4.prefix_len()))
                .or_else(|| {
                    ecs.ipv6.map(|ipv6| {
                        (net::IpAddr::from(ipv6.network()), ipv6.prefix_len())
                    })
                })
        };

        let Some((addr, prefix)) = candidate else {
            return;
        };

        let edns = message
            .extensions_mut()
            .get_or_insert_with(hickory_proto::op::Edns::new);

        let options = edns.options_mut();
        options.remove(EdnsCode::Subnet);
        options.insert(EdnsOption::Subnet(ClientSubnet::new(addr, prefix, prefix)));
    }
}

impl Debug for DnsClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("net", &self.net)
            .field("iface", &self.iface)
            .field("proxy", &self.proxy.name())
            .finish()
    }
}

#[async_trait]
impl Client for DnsClient {
    fn id(&self) -> String {
        format!("{}#{}:{}", &self.net, &self.host, &self.port)
    }

    #[instrument(skip(msg), level = "trace")]
    async fn exchange(&self, msg: &Message) -> anyhow::Result<Message> {
        let need_initialize = {
            let inner = self.inner.read().await;
            inner.c.is_none()
                || inner.bg_handle.as_ref().is_none_or(|bg| bg.is_finished())
        };
        if need_initialize {
            let mut inner = self.inner.write().await;

            match &inner.bg_handle {
                Some(bg) => {
                    if bg.is_finished() {
                        warn!(
                            "dns client background task is finished, likely \
                             connection closed, restarting a new one"
                        );
                        let (client, bg) = dns_stream_builder(&self.cfg).await?;
                        inner.c.replace(client);
                        inner.bg_handle.replace(bg);
                    } else {
                        trace!(
                            "dns client background task is still running, reusing \
                             existing connection"
                        );
                    }
                }
                _ => {
                    // initializing client
                    info!("initializing dns client: {}", &self.cfg);
                    let (client, bg) = dns_stream_builder(&self.cfg).await?;
                    inner.c.replace(client);
                    inner.bg_handle.replace(bg);
                }
            }
        }

        let mut outbound = msg.clone();
        self.apply_edns_client_subnet(&mut outbound);

        let mut req = DnsRequest::new(outbound, DnsRequestOptions::default());
        if req.id() == 0 {
            req.set_id(rand::random::<u16>());
        }
        self.inner
            .read()
            .await
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
    let dns_resolver = Arc::new(dns::SystemResolver::new(false)?);
    match cfg {
        DnsConfig::Udp(addr, iface, proxy) => {
            let stream = UdpClientStream::builder(
                *addr,
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *TUN_SOMARK.read().await,
                ),
            )
            .with_timeout(Some(Duration::from_secs(5)))
            .build();

            client::Client::connect(stream)
                .await
                .map(|(x, y)| (x, tokio::spawn(y)))
                .map_err(|x| Error::DNSError(x.to_string()))
        }
        DnsConfig::Tcp(addr, iface, proxy) => {
            let (stream, sender) = TcpClientStream::new(
                *addr,
                None,
                Some(Duration::from_secs(5)),
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *TUN_SOMARK.read().await,
                ),
            );

            client::Client::new(stream, sender, None)
                .await
                .map(|(x, y)| (x, tokio::spawn(y)))
                .map_err(|x| Error::DNSError(x.to_string()))
        }
        DnsConfig::Tls(addr, host, iface, proxy) => {
            let mut tls_config = ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            tls_config.alpn_protocols = vec!["dot".into(), "h2".into()];

            let addr = *addr;
            let host = host.clone();
            let iface = iface.clone();
            let (stream, sender) = tls_client_connect(
                addr,
                host,
                Arc::new(tls_config),
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *TUN_SOMARK.read().await,
                ),
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
        DnsConfig::Https(addr, host, iface, proxy) => {
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
                DnsRuntimeProvider::new(
                    proxy.clone(),
                    dns_resolver,
                    iface.clone(),
                    *TUN_SOMARK.read().await,
                ),
            )
            .build(*addr, host.to_owned(), "/dns-query".to_string());

            client::Client::connect(stream)
                .await
                .map(|(x, y)| (x, tokio::spawn(y)))
                .map_err(|x| Error::DNSError(x.to_string()))
        }
    }
}
