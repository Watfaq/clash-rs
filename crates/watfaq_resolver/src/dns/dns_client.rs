use std::{
    fmt::{Debug, Display, Formatter, format},
    net::{self, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use futures::{TryFutureExt, future::BoxFuture};
use hickory_client::client;
use hickory_proto::{
    runtime::iocompat::AsyncIoTokioAsStd,
    rustls::{self, tls_client_stream::tls_client_connect_with_future},
    tcp::TcpClientStream,
    udp::UdpClientStream,
};

use ::rustls::ClientConfig;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{info, warn};
use watfaq_error::{ErrContext, Error, Result, anyhow};

use hickory_proto::{
    DnsHandle,
    h2::HttpsClientStreamBuilder,
    op::Message,
    xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
};
use tokio::net::TcpStream as TokioTcpStream;
use watfaq_state::Context;
use watfaq_types::Iface;
use watfaq_utils::{GLOBAL_ROOT_STORE, NoHostnameTlsVerifier};

use crate::{AbstractDnsClient, AbstractResolver, DnsClient, Resolver};

use super::{dhcp::DhcpClient, resolver, runtime::DnsRuntimeProvider};

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

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "UDP" => Ok(Self::Udp),
            "TCP" => Ok(Self::Tcp),
            "DoH" => Ok(Self::DoH),
            "DoT" => Ok(Self::DoT),
            "DHCP" => Ok(Self::Dhcp),
            _ => Err(anyhow!("unsupported protocol")),
        }
    }
}

#[derive(Clone)]
pub struct Opts {
    pub host: String,
    pub port: u16,
    pub net: DNSNetMode,
}

enum DnsConfig {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Tls(SocketAddr, String),
    Https(SocketAddr, String),
}

impl Display for DnsConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            DnsConfig::Udp(addr) => {
                write!(f, "UDP: {}:{} ", addr.ip(), addr.port())?;
                Ok(())
            }
            DnsConfig::Tcp(addr) => {
                write!(f, "TCP: {}:{} ", addr.ip(), addr.port())?;
                Ok(())
            }
            DnsConfig::Tls(addr, host) => {
                write!(f, "TLS: {}:{} ", addr.ip(), addr.port())?;
                write!(f, "host: {}", host)
            }
            DnsConfig::Https(addr, host) => {
                write!(f, "HTTPS: {}:{} ", addr.ip(), addr.port())?;
                write!(f, "host: {}", host)
            }
        }
    }
}

struct Inner {
    c: Option<client::Client>,
    bg_handle: Option<JoinHandle<Result<()>>>,
}

/// DnsClient
pub struct EnhancedDnsClient {
    inner: Arc<RwLock<Inner>>,

    cfg: DnsConfig,

    // debug purpose
    host: String,
    port: u16,
    net: DNSNetMode,
}

impl EnhancedDnsClient {
    pub async fn new(resolver: &Resolver, opts: Opts) -> Result<DnsClient> {
        // TODO: use proxy to connect?
        match &opts.net {
            DNSNetMode::Dhcp => Ok(DhcpClient::new(&opts.host).await.into()),

            other => {
                let ip = match resolver
                    .resolve(&opts.host, false)
                    .await
                    .context("resolve hostname failure {}")?
                {
                    (None, None) => {
                        return Err(anyhow!(
                            "can't resolve default DNS: {}",
                            opts.host
                        ));
                    }
                    (v4, v6) => ip,
                };

                match other {
                    DNSNetMode::Udp => {
                        let cfg =
                            DnsConfig::Udp(net::SocketAddr::new(ip, opts.port));

                        Ok(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,

                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                        }
                        .into())
                    }
                    DNSNetMode::Tcp => {
                        let cfg =
                            DnsConfig::Tcp(net::SocketAddr::new(ip, opts.port));

                        Ok(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,

                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                        }
                        .into())
                    }
                    DNSNetMode::DoT => {
                        let cfg = DnsConfig::Tls(
                            net::SocketAddr::new(ip, opts.port),
                            opts.host.clone(),
                        );

                        Ok(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,

                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                        }
                        .into())
                    }
                    DNSNetMode::DoH => {
                        let cfg = DnsConfig::Https(
                            net::SocketAddr::new(ip, opts.port),
                            opts.host.clone(),
                        );

                        Ok(Self {
                            inner: Arc::new(RwLock::new(Inner {
                                c: None,
                                bg_handle: None,
                            })),

                            cfg,
                            host: opts.host,
                            port: opts.port,
                            net: opts.net,
                        }
                        .into())
                    }
                    _ => unreachable!("."),
                }
            }
        }
    }
}

impl Debug for EnhancedDnsClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("net", &self.net)
            .finish()
    }
}

impl AbstractDnsClient for EnhancedDnsClient {
    fn id(&self) -> String {
        format!("{}#{}:{}", &self.net, &self.host, &self.port)
    }

    async fn exchange(&self, ctx: Arc<Context>, msg: &Message) -> Result<Message> {
        let mut inner = self.inner.write().await;

        match &inner.bg_handle {
            Some(bg) => {
                if bg.is_finished() {
                    warn!(
                        "dns client background task is finished, likely connection \
                         closed, restarting a new one"
                    );
                    let (client, bg) = dns_stream_builder(ctx, &self.cfg).await?;
                    inner.c.replace(client);
                    inner.bg_handle.replace(bg);
                }
            }
            _ => {
                // initializing client
                info!("initializing dns client: {}", &self.cfg);
                let (client, bg) = dns_stream_builder(ctx, &self.cfg).await?;
                inner.c.replace(client);
                inner.bg_handle.replace(bg);
            }
        }

        let mut req = DnsRequest::new(msg.clone(), DnsRequestOptions::default());
        if req.id() == 0 {
            req.set_id(rand::random::<u16>());
        }
        let msg = inner
            .c
            .as_ref()
            .unwrap()
            .send(req)
            .first_answer()
            .await?
            .into_message();
        Ok(msg)
    }
}

async fn dns_stream_builder(
    ctx: Arc<Context>,
    cfg: &DnsConfig,
) -> Result<(client::Client, JoinHandle<Result<()>>)> {
    match cfg {
        DnsConfig::Udp(addr) => {
            let stream =
                UdpClientStream::builder(*addr, DnsRuntimeProvider::new(ctx))
                    .with_timeout(Some(Duration::from_secs(5)))
                    .build();

            let res = client::Client::connect(stream)
                .await
                .map(|(x, y)| (x, tokio::spawn(async { Ok(y.await?) })));
            Ok(res?)
        }
        DnsConfig::Tcp(addr) => {
            let (stream, sender) = TcpClientStream::new(
                *addr,
                None,
                Some(Duration::from_secs(5)),
                DnsRuntimeProvider::new(ctx),
            );

            let res = client::Client::new(stream, sender, None)
                .await
                .map(|(x, y)| (x, tokio::spawn(async { Ok(y.await?) })))?;
            Ok(res)
        }
        DnsConfig::Tls(addr, host) => {
            let mut tls_config = ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            tls_config.alpn_protocols = vec!["dot".into(), "h2".into()];

            let fut = new_tcp_stream(*addr).map_ok(AsyncIoTokioAsStd);

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

            let res = client::Client::with_timeout(
                stream,
                sender,
                Duration::from_secs(5),
                None,
            )
            .await
            .map(|(x, y)| (x, tokio::spawn(async { Ok(y.await?) })))?;
            Ok(res)
        }
        DnsConfig::Https(addr, host) => {
            let mut tls_config = ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            tls_config.alpn_protocols = vec!["h2".into()];

            if host == &addr.ip().to_string() {
                tls_config.dangerous().set_certificate_verifier(Arc::new(
                    NoHostnameTlsVerifier::new(),
                ));
            }

            let stream = HttpsClientStreamBuilder::with_client_config(
                Arc::new(tls_config),
                DnsRuntimeProvider::new(ctx),
            )
            .build(*addr, host.to_owned(), "/dns-query".to_string());

            let res = client::Client::connect(stream)
                .await
                .map(|(x, y)| (x, tokio::spawn(async { Ok(y.await?) })))?;
            Ok(res)
        }
    }
}
