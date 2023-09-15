use std::{io, sync::Arc};

use async_trait::async_trait;
use bytes::BufMut;
use bytes::BytesMut;
use futures::TryFutureExt;
use sha2::Digest;
use sha2::Sha224;
use tokio::io::AsyncWriteExt;

use crate::app::dispatcher::ChainedStream;
use crate::app::dispatcher::ChainedStreamWrapper;
use crate::common::utils;
use crate::{
    app::{dispatcher::BoxedChainedStream, dns::ThreadSafeDNSResolver},
    session::{Session, SocksAddr},
};

use self::datagram::OutboundDatagramTrojan;

use super::transport;
use super::transport::TLSOptions;
use super::{
    options::{GrpcOption, WsOption},
    utils::new_tcp_stream,
    AnyOutboundDatagram, AnyOutboundHandler, AnyStream, CommonOption, OutboundHandler,
    OutboundType,
};

mod datagram;
mod stream;

static DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

pub enum Transport {
    Ws(WsOption),
    Grpc(GrpcOption),
}

pub struct Opts {
    pub name: String,
    pub common_opts: CommonOption,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub udp: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: bool,
    pub transport: Option<Transport>,
}

pub struct Handler {
    opts: Opts,
}

impl Handler {
    pub fn new(opts: Opts) -> AnyOutboundHandler {
        Arc::new(Self { opts })
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Trojan
    }

    async fn remote_addr(&self) -> Option<SocksAddr> {
        Some(SocksAddr::Domain(self.opts.server.clone(), self.opts.port))
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let stream = new_tcp_stream(
            resolver.clone(),
            self.opts.server.as_str(),
            self.opts.port,
            self.opts.common_opts.iface.as_ref(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        )
        .map_err(|x| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "dial outbound {}:{}: {}",
                    self.opts.server, self.opts.port, x
                ),
            )
        })
        .await?;

        let stream = self.proxy_stream(stream, sess, resolver).await?;

        let chained = ChainedStreamWrapper::new(stream);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        _: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let tls_opt = TLSOptions {
            skip_cert_verify: self.opts.skip_cert_verify,
            sni: self.opts.sni.clone(),
            alpn: self.opts.alpn.clone().or(Some(
                DEFAULT_ALPN
                    .to_vec()
                    .into_iter()
                    .map(|x| x.to_owned())
                    .collect::<Vec<String>>(),
            )),
        };

        let mut s = transport::tls::wrap_stream(s, tls_opt.to_owned()).await?;

        let mut buf = BytesMut::new();
        let password = Sha224::digest(self.opts.password.as_bytes());
        let password = utils::encode_hex(&password[..]);
        buf.put_slice(password.as_bytes());
        buf.put_slice(b"\r\n");
        buf.put_u8(0x01); // tcp
        sess.destination.write_buf(&mut buf);
        buf.put_slice(b"\r\n");
        s.write_all(&buf).await?;

        Ok(s)
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        let stream = new_tcp_stream(
            resolver.clone(),
            self.opts.server.as_str(),
            self.opts.port,
            self.opts.common_opts.iface.as_ref(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        )
        .map_err(|x| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "dial outbound {}:{}: {}",
                    self.opts.server, self.opts.port, x
                ),
            )
        })
        .await?;

        let stream = self.proxy_stream(stream, sess, resolver).await?;
        Ok(Box::new(OutboundDatagramTrojan::new(
            stream,
            sess.destination.clone(),
        )))
    }
}
