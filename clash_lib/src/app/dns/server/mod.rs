use std::time::Duration;

use async_trait::async_trait;

use hickory_proto::{
    op::{Header, Message, MessageType, OpCode, ResponseCode},
    rr::RecordType,
};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

use crate::Runner;

use super::{Config, ThreadSafeDNSResolver};

struct DnsListener {
    server: ServerFuture<DnsHandler>,
}

struct DnsHandler {
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

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());

        if request.query().query_type() == RecordType::AAAA && !self.resolver.ipv6() {
            header.set_authoritative(true);

            let resp = builder.build_no_records(header);
            return Ok(response_handle.send_response(resp).await?);
        }

        let mut m = Message::new();
        m.set_op_code(request.op_code());
        m.set_message_type(request.message_type());
        m.set_recursion_desired(request.recursion_desired());
        m.add_query(request.query().original().clone());
        m.add_additionals(request.additionals().into_iter().map(Clone::clone));
        m.add_name_servers(request.name_servers().into_iter().map(Clone::clone));
        for sig0 in request.sig0() {
            m.add_sig0(sig0.clone());
        }
        if let Some(edns) = request.edns() {
            m.set_edns(edns.clone());
        }

        match self.resolver.exchange(m).await {
            Ok(m) => {
                header.set_recursion_available(m.recursion_available());
                header.set_response_code(m.response_code());
                header.set_authoritative(m.authoritative());

                header.set_answer_count(m.answer_count());
                header.set_name_server_count(m.name_server_count());
                header.set_additional_count(m.additional_count());

                let mut rv =
                    builder.build(header, m.answers(), m.name_servers(), &[], m.additionals());

                if let Some(edns) = request.edns() {
                    if edns.dnssec_ok() {
                        if let Some(edns) = m.extensions() {
                            rv.set_edns(edns.clone());
                        }
                    }
                }

                debug!(
                    "answering dns query {} with answer {:?}",
                    request.query().name(),
                    m.answers(),
                );

                Ok(response_handle.send_response(rv).await?)
            }
            Err(e) => {
                debug!("dns resolve error: {}", e);
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
            "got dns request [{}][{}][{}] from {}",
            request.protocol(),
            request.query().query_type(),
            request.query().name(),
            request.src()
        );

        match self.handle(request, response_handle).await {
            Ok(info) => info,
            Err(e) => {
                debug!("dns request error: {}", e);
                let mut h = Header::new();
                h.set_response_code(ResponseCode::ServFail);
                h.into()
            }
        }
    }
}

static DEFAULT_DNS_SERVER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn get_dns_listener(cfg: Config, resolver: ThreadSafeDNSResolver) -> Option<Runner> {
    if !cfg.enable {
        return None;
    }

    let h = DnsHandler { resolver };
    let mut s = ServerFuture::new(h);

    if let Some(addr) = cfg.listen.udp {
        UdpSocket::bind(addr)
            .await
            .map(|x| {
                info!("dns server listening on udp: {}", addr);
                s.register_socket(x);
            })
            .ok()?;
    }
    if let Some(addr) = cfg.listen.tcp {
        TcpListener::bind(addr)
            .await
            .map(|x| {
                info!("dns server listening on tcp: {}", addr);
                s.register_listener(x, DEFAULT_DNS_SERVER_TIMEOUT);
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

    let mut l = DnsListener { server: s };

    Some(Box::pin(async move {
        l.server.block_until_done().await.map_err(|x| {
            warn!("dns server error: {}", x);
            crate::Error::DNSError(format!("dns server error: {}", x))
        })
    }))
}
