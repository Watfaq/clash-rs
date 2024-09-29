mod dummy_keys;
mod utils;

use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;

use hickory_proto::{
    op::{Header, Message, MessageType, OpCode, ResponseCode},
    rr::{
        rdata::{A, AAAA},
        RData, Record, RecordType,
    },
};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};
use utils::{load_default_cert, load_default_key};

use crate::Runner;

use super::{config::DNSListenAddr, ThreadSafeDNSResolver};

static DEFAULT_DNS_SERVER_TTL: u32 = 60;

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

        if request.query().query_type() == RecordType::AAAA && !self.resolver.ipv6()
        {
            header.set_authoritative(true);

            let resp = builder.build_no_records(header);
            return Ok(response_handle.send_response(resp).await?);
        }

        if self.resolver.fake_ip_enabled() {
            let name = request.query().name();
            let host = if name.is_fqdn() {
                name.to_string().strip_suffix('.').unwrap().to_string()
            } else {
                name.to_string()
            };

            let builder = MessageResponseBuilder::from_message_request(request);
            let mut header = Header::response_from_request(request.header());
            header.set_authoritative(true);

            match self.resolver.resolve(&host, true).await {
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

                        let resp =
                            builder.build(header, records.iter(), &[], &[], &[]);
                        return Ok(response_handle.send_response(resp).await?);
                    }
                    None => {
                        let resp = builder.build_no_records(header);
                        return Ok(response_handle.send_response(resp).await?);
                    }
                },
                Err(e) => {
                    debug!("dns resolve error: {}", e);
                    return Err(DNSError::QueryFailed(e.to_string()));
                }
            }
        }

        let mut m = Message::new();
        m.set_op_code(request.op_code());
        m.set_message_type(request.message_type());
        m.set_recursion_desired(request.recursion_desired());
        m.add_query(request.query().original().clone());
        m.add_additionals(request.additionals().iter().map(Clone::clone));
        m.add_name_servers(request.name_servers().iter().map(Clone::clone));
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

                let mut rv = builder.build(
                    header,
                    m.answers(),
                    m.name_servers(),
                    &[],
                    m.additionals(),
                );

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

pub async fn get_dns_listener(
    listen: DNSListenAddr,
    resolver: ThreadSafeDNSResolver,
    cwd: &std::path::Path,
) -> Option<Runner> {
    let h = DnsHandler { resolver };
    let mut s = ServerFuture::new(h);

    let mut has_server = false;

    if let Some(addr) = listen.udp {
        has_server = true;
        UdpSocket::bind(addr)
            .await
            .map(|x| {
                info!("UDP dns server listening on: {}", addr);
                s.register_socket(x);
            })
            .ok()?;
    }
    if let Some(addr) = listen.tcp {
        has_server = true;
        TcpListener::bind(addr)
            .await
            .map(|x| {
                info!("TCP dns server listening on: {}", addr);
                s.register_listener(x, DEFAULT_DNS_SERVER_TIMEOUT);
            })
            .ok()?;
    }
    if let Some(c) = listen.doh {
        has_server = true;
        TcpListener::bind(c.addr)
            .await
            .and_then(|x| {
                info!("DoH server listening on: {}", c.addr);
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!("using custom key and cert for doh: {}/{}", k, c);
                }

                let server_key = c
                    .ca_key
                    .map(|x| utils::load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| utils::load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_https_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    (server_cert, server_key),
                    c.hostname,
                )?;
                Ok(())
            })
            .ok()?;
    }
    if let Some(c) = listen.dot {
        has_server = true;
        TcpListener::bind(c.addr)
            .await
            .and_then(|x| {
                info!("DoT dns server listening on: {}", c.addr);
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!("using custom key and cert for dot: {}/{}", k, c);
                }

                let server_key = c
                    .ca_key
                    .map(|x| utils::load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| utils::load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_tls_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    (server_cert, server_key),
                )?;
                Ok(())
            })
            .ok()?;
    }

    if let Some(c) = listen.doh3 {
        has_server = true;
        UdpSocket::bind(c.addr)
            .await
            .and_then(|x| {
                info!("DoT3 dns server listening on: {}", c.addr);
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!("using custom key and cert for dot: {}/{}", k, c);
                }

                let server_key = c
                    .ca_key
                    .map(|x| utils::load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| utils::load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_h3_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    (server_cert, server_key),
                    c.hostname,
                )?;
                Ok(())
            })
            .ok()?;
    }

    if !has_server {
        return None;
    }

    let mut l = DnsListener { server: s };

    Some(Box::pin(async move {
        l.server.block_until_done().await.map_err(|x| {
            warn!("dns server error: {}", x);
            crate::Error::DNSError(format!("dns server error: {}", x))
        })
    }))
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use hickory_client::{
        client::{self, AsyncClient, ClientHandle},
        proto::iocompat::AsyncIoTokioAsStd,
    };
    use hickory_proto::{
        h2::HttpsClientStreamBuilder,
        h3::H3ClientStreamBuilder,
        rr::{rdata::A, DNSClass, Name, RData, RecordType},
        rustls::tls_client_connect,
        tcp::TcpClientStream,
        udp::UdpClientStream,
    };
    use rustls::ClientConfig;
    use tokio::net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};

    use crate::{
        app::dns::MockClashResolver,
        common::tls::{self, GLOBAL_ROOT_STORE},
        tests::initialize,
    };

    async fn send_query(client: &mut AsyncClient) {
        // Specify the name, note the final '.' which specifies it's an FQDN
        let name = Name::from_ascii("www.example.com.").unwrap();

        // NOTE: see 'Setup a connection' example above
        // Send the query and get a message response, see RecordType for all
        // supported options
        let response = client
            .query(name, DNSClass::IN, RecordType::A)
            .await
            .unwrap();

        // Messages are the packets sent between client and server in DNS.
        //  there are many fields to a Message, DnsResponse can be dereferenced into
        //  a Message. It's beyond the scope of these examples
        //  to explain all the details of a Message. See
        // hickory_client::op::message::Message for more details.  generally
        // we will be interested in the Message::answers
        let answers = response.answers();

        // Records are generic objects which can contain any data.
        //  In order to access it we need to first check what type of record it is
        //  In this case we are interested in A, IPv4 address
        if let RData::A(ref ip) = answers[0].data() {
            assert_eq!(*ip, A::new(93, 184, 215, 14))
        } else {
            unreachable!("unexpected result")
        }
    }

    #[tokio::test]
    async fn test_multiple_dns_server() {
        initialize();

        let mut resolver = MockClashResolver::new();
        resolver.expect_fake_ip_enabled().returning(|| false);
        resolver.expect_exchange().returning(|_| {
            let mut m = hickory_proto::op::Message::new();
            m.set_response_code(hickory_proto::op::ResponseCode::NoError);
            m.add_answer(hickory_proto::rr::Record::from_rdata(
                "www.example.com".parse().unwrap(),
                60,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                    std::net::Ipv4Addr::new(93, 184, 215, 14),
                )),
            ));
            Ok(m)
        });

        let cfg = crate::app::dns::config::DNSListenAddr {
            udp: Some("127.0.0.1:53553".parse().unwrap()),
            tcp: Some("127.0.0.1:53554".parse().unwrap()),
            dot: Some(crate::app::dns::config::DoTConfig {
                addr: "127.0.0.1:53555".parse().unwrap(),
                ca_key: None,
                ca_cert: None,
            }),
            doh: Some(crate::app::dns::config::DoHConfig {
                addr: "127.0.0.1:53556".parse().unwrap(),
                hostname: Some("dns.example.com".to_string()),
                ca_key: None,
                ca_cert: None,
            }),
            doh3: Some(crate::app::dns::config::DoH3Config {
                addr: "127.0.0.1:53556".parse().unwrap(),
                hostname: Some("dns.example.com".to_string()),
                ca_key: None,
                ca_cert: None,
            }),
        };
        let listener = super::get_dns_listener(
            cfg,
            Arc::new(resolver),
            std::path::Path::new("."),
        )
        .await;

        assert!(listener.is_some());
        tokio::spawn(async move {
            listener.unwrap().await.unwrap();
        });

        let stream = UdpClientStream::<TokioUdpSocket>::new(
            "127.0.0.1:53553".parse().unwrap(),
        );
        let (mut client, handle) =
            client::AsyncClient::connect(stream).await.unwrap();
        tokio::spawn(handle);

        send_query(&mut client).await;

        let (stream, sender) =
            TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(
                "127.0.0.1:53554".parse().unwrap(),
            );

        let (mut client, handle) = client::AsyncClient::new(stream, sender, None)
            .await
            .unwrap();
        tokio::spawn(handle);

        send_query(&mut client).await;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["h2".into()];
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let (stream, sender) = tls_client_connect::<AsyncIoTokioAsStd<TokioTcpStream>>(
            "127.0.0.1:53555".parse().unwrap(),
            "dns.example.com".to_owned(),
            Arc::new(tls_config),
        );

        let (mut client, handle) = client::AsyncClient::with_timeout(
            stream,
            sender,
            Duration::from_secs(5),
            None,
        )
        .await
        .unwrap();
        tokio::spawn(handle);

        send_query(&mut client).await;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["h2".into()];

        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let stream =
            HttpsClientStreamBuilder::with_client_config(Arc::new(tls_config))
                .build::<AsyncIoTokioAsStd<TokioTcpStream>>(
                "127.0.0.1:53556".parse().unwrap(),
                "dns.example.com".to_owned(),
            );

        let (mut client, handle) =
            client::AsyncClient::connect(stream).await.unwrap();
        tokio::spawn(handle);

        send_query(&mut client).await;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["h3".into()];

        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let stream = H3ClientStreamBuilder::default()
            .crypto_config(tls_config)
            .clone()
            .build(
                "127.0.0.1:53556".parse().unwrap(),
                "dns.example.com".to_owned(),
            );

        let (mut client, handle) =
            client::AsyncClient::connect(stream).await.unwrap();
        tokio::spawn(handle);

        send_query(&mut client).await;
    }
}
