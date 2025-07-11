use crate::{
    DNSListenAddr, DnsMessageExchanger,
    utils::{
        load_cert_chain, load_default_cert, load_default_key, load_priv_key,
        new_io_error,
    },
};
use async_trait::async_trait;
use hickory_proto::{
    op::{Header, Message, MessageType, OpCode, ResponseCode},
    rr::RecordType,
};
use hickory_server::{
    ServerFuture,
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
#[cfg(feature = "aws-lc-rs")]
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
#[cfg(feature = "ring")]
use rustls::crypto::ring::sign::any_supported_type;
use rustls::{server::AlwaysResolvesServerRawPublicKeys, sign::CertifiedKey};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

struct CertificateKeyPair {
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl From<CertificateKeyPair> for Arc<dyn rustls::server::ResolvesServerCert> {
    fn from(pair: CertificateKeyPair) -> Self {
        Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            CertifiedKey::new(pair.certs, any_supported_type(&pair.key).unwrap()),
        )))
    }
}

struct DnsListener<H: RequestHandler> {
    server: ServerFuture<H>,
}

struct DnsHandler<X> {
    exchanger: X,
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

impl<X> DnsHandler<X>
where
    X: DnsMessageExchanger,
{
    async fn handle<H: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: H,
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

        let query = request
            .queries()
            .first()
            .ok_or(DNSError::QueryFailed("no query".to_string()))?;

        if query.query_type() == RecordType::AAAA && !self.exchanger.ipv6() {
            header.set_authoritative(true);

            let resp = builder.build_no_records(header);
            return Ok(response_handle.send_response(resp).await?);
        }

        let mut m = Message::new();
        m.set_op_code(request.op_code());
        m.set_message_type(request.message_type());
        m.set_recursion_desired(request.recursion_desired());
        m.add_query(query.original().clone());
        m.add_additionals(request.additionals().iter().cloned());
        m.add_name_servers(request.name_servers().iter().cloned());
        for sig0 in request.sig0() {
            m.add_sig0(sig0.clone());
        }
        if let Some(edns) = request.edns() {
            m.set_edns(edns.clone());
        }

        match self.exchanger.exchange(&m).await {
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
                    if edns.flags().dnssec_ok {
                        if let Some(edns) = m.extensions() {
                            rv.set_edns(edns.clone());
                        }
                    }
                }

                debug!(
                    "answering dns query {} with answer {:?}",
                    query.name(),
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
impl<X> RequestHandler for DnsHandler<X>
where
    X: DnsMessageExchanger + Unpin + Send + Sync + 'static,
{
    async fn handle_request<H: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: H,
    ) -> ResponseInfo {
        debug!(
            "got dns request [{}][{:?}][{:?}] from {}",
            request.protocol(),
            request.queries().first().map(|x| x.query_type()),
            request.queries().first().map(|x| x.name()),
            request.src()
        );

        self.handle(request, response_handle)
            .await
            .unwrap_or_else(|e| {
                debug!("dns request error: {}", e);
                let mut h = Header::new();
                h.set_response_code(ResponseCode::ServFail);
                h.into()
            })
    }
}

static DEFAULT_DNS_SERVER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn get_dns_listener<X>(
    listen: DNSListenAddr,
    exchanger: X,
    cwd: &std::path::Path,
) -> Option<futures::future::BoxFuture<'static, Result<(), DNSError>>>
where
    X: DnsMessageExchanger + Sync + Send + Unpin + 'static,
{
    let handler = DnsHandler { exchanger };
    let mut s = ServerFuture::new(handler);

    let mut has_server = false;

    if let Some(addr) = listen.udp {
        has_server = UdpSocket::bind(addr)
            .await
            .map(|x| {
                info!("UDP dns server listening on: {}", addr);
                s.register_socket(x);
            })
            .inspect_err(|x| {
                error!("failed to listen UDP DNS server on {}: {}", addr, x);
            })
            .is_ok();
    }
    if let Some(addr) = listen.tcp {
        has_server |= TcpListener::bind(addr)
            .await
            .map(|x| {
                info!("TCP dns server listening on: {}", addr);
                s.register_listener(x, DEFAULT_DNS_SERVER_TIMEOUT);
            })
            .inspect_err(|x| {
                error!("failed to listen TCP DNS server on {}: {}", addr, x);
            })
            .is_ok();
    }
    if let Some(c) = listen.doh {
        has_server |= TcpListener::bind(c.addr)
            .await
            .and_then(|x| {
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!(
                        "using custom key and cert for DoH: {:?}/{:?}",
                        cwd.join(k),
                        cwd.join(c)
                    );
                }

                let server_key = c
                    .ca_key
                    .map(|x| load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_https_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    CertificateKeyPair {
                        certs: server_cert,
                        key: server_key,
                    }
                    .into(),
                    c.hostname,
                    "/dns-query".to_string(),
                )?;
                info!("DoH server listening on: {}", c.addr);
                Ok(())
            })
            .inspect_err(|x| {
                error!("failed to listen DoH server on {}: {}", c.addr, x);
            })
            .is_ok();
    }
    if let Some(c) = listen.dot {
        has_server |= TcpListener::bind(c.addr)
            .await
            .and_then(|x| {
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!(
                        "using custom key and cert for DoT: {:?}/{:?}",
                        cwd.join(k),
                        cwd.join(c)
                    );
                }

                let server_key = c
                    .ca_key
                    .map(|x| load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_tls_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    CertificateKeyPair {
                        certs: server_cert,
                        key: server_key,
                    }
                    .into(),
                )?;
                info!("DoT dns server listening on: {}", c.addr);
                Ok(())
            })
            .inspect_err(|x| {
                error!("failed to listen DoT DNS server on {}: {}", c.addr, x);
            })
            .is_ok();
    }

    if let Some(c) = listen.doh3 {
        has_server |= UdpSocket::bind(c.addr)
            .await
            .and_then(|x| {
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!(
                        "using custom key and cert for DoH3: {:?}/{:?}",
                        cwd.join(k),
                        cwd.join(c)
                    );
                }

                let server_key = c
                    .ca_key
                    .map(|x| load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_h3_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    CertificateKeyPair {
                        certs: server_cert,
                        key: server_key,
                    }
                    .into(),
                    c.hostname,
                )?;
                info!("DoT3 dns server listening on: {}", c.addr);
                Ok(())
            })
            .inspect_err(|x| {
                error!("failed to listen DoH3 DNS server on {}: {}", c.addr, x);
            })
            .is_ok();
    }

    if !has_server {
        return None;
    }

    let mut l = DnsListener { server: s };

    Some(Box::pin(async move {
        info!("starting DNS server");
        l.server.block_until_done().await.map_err(|x| {
            warn!("dns server error: {}", x);
            DNSError::Io(new_io_error(format!("dns server error: {}", x)))
        })
    }))
}

#[cfg(test)]
mod tests {
    use crate::{
        DNSListenAddr, DoH3Config, DoHConfig, DoTConfig, MockDnsMessageExchanger,
        tests::setup_default_crypto_provider,
        tls::{self, global_root_store},
    };
    use futures::FutureExt;
    use hickory_client::client::{self, Client, ClientHandle};
    use hickory_proto::{
        h2::HttpsClientStreamBuilder,
        h3::H3ClientStreamBuilder,
        rr::{DNSClass, Name, RData, RecordType, rdata::A},
        runtime::TokioRuntimeProvider,
        rustls::tls_client_connect,
        tcp::TcpClientStream,
        udp::UdpClientStream,
    };
    use rustls::ClientConfig;
    use std::{sync::Arc, time::Duration};

    async fn send_query(client: &mut Client) {
        let name = Name::from_ascii("www.example.com.").unwrap();

        let response = client
            .query(name, DNSClass::IN, RecordType::A)
            .await
            .unwrap();

        let answers = response.answers();

        if let RData::A(ip) = answers[0].data() {
            assert_eq!(*ip, A::new(93, 184, 215, 14))
        } else {
            unreachable!("unexpected result")
        }
    }

    #[tokio::test]
    async fn test_multiple_dns_server() {
        setup_default_crypto_provider();
        env_logger::init();

        let mut mock_exchanger = MockDnsMessageExchanger::new();
        mock_exchanger.expect_ipv6().returning(|| false);
        mock_exchanger.expect_exchange().returning(|_| {
            async {
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
            }
            .boxed()
        });

        let cfg = DNSListenAddr {
            udp: Some("127.0.0.1:53553".parse().unwrap()),
            tcp: Some("127.0.0.1:53554".parse().unwrap()),
            dot: Some(DoTConfig {
                addr: "127.0.0.1:53555".parse().unwrap(),
                ca_key: None,
                ca_cert: None,
            }),
            doh: Some(DoHConfig {
                addr: "127.0.0.1:53556".parse().unwrap(),
                hostname: Some("dns.example.com".to_string()),
                ca_key: None,
                ca_cert: None,
            }),
            doh3: Some(DoH3Config {
                addr: "127.0.0.1:53557".parse().unwrap(),
                hostname: Some("dns.example.com".to_string()),
                ca_key: None,
                ca_cert: None,
            }),
        };

        let listener =
            super::get_dns_listener(cfg, mock_exchanger, std::path::Path::new("."))
                .await;

        assert!(listener.is_some());
        tokio::spawn(async move {
            listener.unwrap().await.unwrap();
        });

        let stream = UdpClientStream::<TokioRuntimeProvider>::builder(
            "127.0.0.1:53553".parse().unwrap(),
            TokioRuntimeProvider::new(),
        )
        .build();

        let (mut client, handle) = client::Client::connect(stream).await.unwrap();
        tokio::spawn(handle);

        send_query(&mut client).await;

        let (stream, sender) = TcpClientStream::new(
            "127.0.0.1:53554".parse().unwrap(),
            None,
            None,
            TokioRuntimeProvider::new(),
        );

        let (mut client, handle) =
            client::Client::new(stream, sender, None).await.unwrap();
        tokio::spawn(handle);

        send_query(&mut client).await;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(global_root_store().clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["dot".into()];
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let (stream, sender) = tls_client_connect::<TokioRuntimeProvider>(
            "127.0.0.1:53555".parse().unwrap(),
            "dns.example.com".to_owned(),
            Arc::new(tls_config),
            TokioRuntimeProvider::new(),
        );

        let (mut client, handle) = client::Client::with_timeout(
            stream,
            sender,
            Duration::from_secs(5),
            None,
        )
        .await
        .inspect_err(|e| {
            assert!(false, "Failed to connect to DoT server: {}", e);
        })
        .unwrap();
        tokio::spawn(handle);

        send_query(&mut client).await;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(global_root_store().clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["h2".into()];

        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let stream = HttpsClientStreamBuilder::with_client_config(
            Arc::new(tls_config),
            TokioRuntimeProvider::new(),
        )
        .build(
            "127.0.0.1:53556".parse().unwrap(),
            "dns.example.com".to_owned(),
            "/dns-query".to_owned(),
        );

        let (mut client, handle) = client::Client::connect(stream).await.unwrap();
        tokio::spawn(handle);

        send_query(&mut client).await;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(global_root_store().clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["h3".into()];

        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let stream = H3ClientStreamBuilder::default()
            .crypto_config(tls_config)
            .clone()
            .build(
                "127.0.0.1:53557".parse().unwrap(),
                "dns.example.com".to_owned(),
                "/dns-query".to_owned(),
            );

        let (mut client, handle) = client::Client::connect(stream).await.unwrap();
        tokio::spawn(handle);

        send_query(&mut client).await;
    }
}
