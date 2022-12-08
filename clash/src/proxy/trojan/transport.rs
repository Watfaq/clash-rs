use std::{io, sync::Arc};

use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    webpki::{DNSNameRef, DnsNameRef},
    TlsConnector,
};

use crate::{
    common::tls,
    proxy::{AnyStream, ProxyStream},
};

const MAX_LENGTH: usize = 8192;

const DEFAULT_ALPN: [&'static str; 2] = ["h2", "http/1.1"];

type Command = u8;

const COMMAND_TCP: Command = 1;
const COMMAND_UDP: Command = 3;

pub struct Opt {
    pub password: String,
    pub alpn: Option<Vec<String>>,
    pub server_name: String,
    pub skip_cert_verify: bool,
}

pub struct WebsocketOpt {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub headers: http::HeaderMap,
}

pub struct Trojan<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) opt: Opt,
    pub(crate) stream: T,
}

impl<T> Trojan<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn new(opt: Opt, stream: T) -> io::Result<T> {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let mut tls_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = opt
            .alpn
            .unwrap_or_else(|| DEFAULT_ALPN.iter().map(|x| x.to_string()).collect())
            .into_iter()
            .map(|x| x.as_bytes().to_vec())
            .collect();

        if opt.skip_cert_verify {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(tls::NoHostnameTlsVerifier));
        }

        let connector = TlsConnector::from(Arc::new(tls_config));
        let dns_name = ServerName::try_from(opt.server_name.as_str())
            .expect(format!("invalid server name: {}", opt.server_name).as_str());

        connector
            .connect(dns_name, stream)
            .await
            .map(|x| x.into_inner().0)
    }
}
