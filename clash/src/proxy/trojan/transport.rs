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
        unimplemented!("Trojan::new")
    }
}
