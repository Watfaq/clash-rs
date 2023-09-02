use std::{net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;

use thiserror::Error;
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::RwLock,
};
use tracing::{debug, info, warn};
use trust_dns_proto::{
    op::{Header, MessageType, OpCode, ResponseCode},
    rr::{
        rdata::{A, AAAA},
        RData, Record, RecordType,
    },
};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};

use crate::{app::ThreadSafeDNSResolver, common::trie, Runner};

use super::{fakeip::FakeDns, Config};

struct DnsListener {
    server: ServerFuture<DnsHandler>,
}

struct DnsHandler {
    hosts: Option<trie::StringTrie<IpAddr>>,
    fake_dns: Option<Arc<RwLock<FakeDns>>>,
    resolver: ThreadSafeDNSResolver,
}

#[derive(Error, Debug)]
pub enum DNSError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid OP code: {0}")]
    InvalidOpQuery(String),
    #[error("query failed: {0}")]
    QueryFailed(String),
}

static DEFAULT_DNS_SERVER_TTL: u32 = 60;

impl DnsHandler {
    async fn handle<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> Result<ResponseInfo, DNSError> {
        if request.op_code() != OpCode::Query {
            return Err(DNSError::InvalidOpQuery(format!(
                "invalid OP code: {}",
                request.op_code()
            )));
        }

        if request.message_type() != MessageType::Query {
            return Err(DNSError::InvalidOpQuery(format!(
                "invalid message type: {}",
                request.message_type()
            )));
        }

        let name = request.query().name();
        let host = if name.is_fqdn() {
            name.to_string().strip_suffix(".").unwrap().to_string()
        } else {
            name.to_string()
        };

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);

        if let Some(hosts) = &self.hosts {
            if let Some(ip) = hosts.search(&host) {
                let rdata = match ip.get_data().unwrap() {
                    IpAddr::V4(a) => RData::A(A(*a)),
                    IpAddr::V6(aaaa) => RData::AAAA(AAAA(*aaaa)),
                };

                let records = vec![Record::from_rdata(
                    name.clone().into(),
                    DEFAULT_DNS_SERVER_TTL,
                    rdata,
                )];

                let resp = builder.build(header, records.iter(), &[], &[], &[]);
                return Ok(response_handle.send_response(resp).await?);
            }
        }
        if let Some(fake_dns) = &self.fake_dns {
            let mut dns_guard = fake_dns.write().await;
            if request.query().original().query_type() == RecordType::A {
                if !dns_guard.should_skip(&host) {
                    let ip = dns_guard.lookup(&host).await;

                    let rdata = match ip {
                        IpAddr::V4(a) => RData::A(A(a)),
                        IpAddr::V6(aaaa) => RData::AAAA(AAAA(aaaa)),
                    };

                    let records = vec![Record::from_rdata(
                        name.into(),
                        DEFAULT_DNS_SERVER_TTL,
                        rdata,
                    )];

                    let resp = builder.build(header, records.iter(), &[], &[], &[]);
                    return Ok(response_handle.send_response(resp).await?);
                }
            }
        }

        match self.resolver.resolve(&host).await {
            Ok(resp) => match resp {
                Some(ip) => {
                    let rdata = match ip {
                        IpAddr::V4(a) => RData::A(A(a)),
                        IpAddr::V6(aaaa) => RData::AAAA(AAAA(aaaa)),
                    };

                    let records = vec![Record::from_rdata(
                        name.into(),
                        DEFAULT_DNS_SERVER_TTL,
                        rdata,
                    )];

                    let resp = builder.build(header, records.iter(), &[], &[], &[]);
                    Ok(response_handle.send_response(resp).await?)
                }
                None => {
                    let resp = builder.build_no_records(header);
                    Ok(response_handle.send_response(resp).await?)
                }
            },
            Err(e) => {
                warn!("dns resolve error: {}", e);
                Err(DNSError::QueryFailed(e.to_string()))
            }
        }
    }
}

#[async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        debug!(
            "got dns request {}-{} from {}",
            request.protocol(),
            request.message_type(),
            request.src()
        );

        match self.handle(request, response_handle).await {
            Ok(info) => info,
            Err(e) => {
                warn!("dns request error: {}", e);
                let mut h = Header::new();
                h.set_response_code(ResponseCode::ServFail);
                h.into()
            }
        }
    }
}

static DEFAULT_DNS_SERVER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn get_dns_listener(cfg: Config, resolver: ThreadSafeDNSResolver) -> Option<Runner> {
    let h = DnsHandler {
        hosts: cfg.hosts,
        fake_dns: cfg.fake_dns.map(|x| Arc::new(RwLock::new(x))),
        resolver,
    };
    let mut s = ServerFuture::new(h);

    if let Some(addr) = cfg.listen.udp {
        UdpSocket::bind(addr)
            .await
            .and_then(|x| {
                info!("dns server listening on udp: {}", addr);
                s.register_socket(x);
                Ok(())
            })
            .ok()?;
    }
    if let Some(addr) = cfg.listen.tcp {
        TcpListener::bind(addr)
            .await
            .and_then(|x| {
                info!("dns server listening on tcp: {}", addr);
                s.register_listener(x, DEFAULT_DNS_SERVER_TIMEOUT);
                Ok(())
            })
            .ok()?;
    }
    if let Some(c) = cfg.listen.doh {
        TcpListener::bind(c.0)
            .await
            .and_then(|x| {
                info!("dns server listening on doh: {}", c.0);
                s.register_https_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    c.1.certificate_and_key,
                    c.1.dns_hostname,
                )?;
                Ok(())
            })
            .ok()?;
    }
    if let Some(c) = cfg.listen.dot {
        TcpListener::bind(c.0)
            .await
            .and_then(|x| {
                info!("dns server listening on dot: {}", c.0);
                s.register_tls_listener(x, DEFAULT_DNS_SERVER_TIMEOUT, c.1.certificate_and_key)?;
                Ok(())
            })
            .ok()?;
    }

    let l = DnsListener { server: s };

    Some(Box::pin(async move {
        match l.server.block_until_done().await {
            Ok(_) => {}
            Err(e) => {
                warn!("dns server error: {}", e);
            }
        }
    }))
}
