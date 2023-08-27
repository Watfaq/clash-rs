use std::{collections::HashMap, io, net::IpAddr, sync::Arc};

use async_trait::async_trait;
use erased_serde::Serialize;
use futures::TryFutureExt;
use http::Uri;

mod vmess_impl;

use crate::{
    app::ThreadSafeDNSResolver,
    common::errors::{map_io_error, new_io_error},
    session::{Session, SocksAddr},
};

use self::vmess_impl::OutboundDatagramVmess;

use super::{
    transport::{self, Http2Config},
    utils::new_tcp_stream,
    AnyOutboundDatagram, AnyOutboundHandler, AnyStream, CommonOption, OutboundHandler,
    OutboundType,
};

pub struct HttpOption {
    pub method: String,
    pub path: Vec<String>,
    pub headers: HashMap<String, String>,
}

pub struct Http2Option {
    pub host: Vec<String>,
    pub path: String,
}

pub struct GrpcOption {
    pub service_name: String,
}

pub struct WsOption {
    pub path: String,
    pub headers: HashMap<String, String>,
    pub max_early_data: usize,
    pub early_data_header_name: String,
}

pub enum VmessTransport {
    Ws(WsOption),
    H2(Http2Option),
    Grpc(GrpcOption),
    Http(HttpOption),
}

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: CommonOption,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub alter_id: u16,
    pub security: String,
    pub udp: bool,
    pub transport: Option<VmessTransport>,
    pub tls: Option<transport::TLSOptions>,
}

pub struct Handler {
    opts: HandlerOptions,
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> AnyOutboundHandler {
        Arc::new(Self { opts })
    }

    async fn inner_proxy_stream<'a>(
        &'a self,
        s: AnyStream,
        sess: &'a Session,
        udp: bool,
    ) -> io::Result<AnyStream> {
        let mut stream = s;

        let underlying = match self.opts.transport {
            Some(VmessTransport::Ws(ref opt)) => {
                let uri = format!("ws://{}:{}{}", self.opts.server, self.opts.port, opt.path)
                    .parse::<Uri>()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                let ws_builder = transport::WebsocketStreamBuilder::new(
                    uri,
                    opt.headers.clone(),
                    None,
                    opt.max_early_data,
                    opt.early_data_header_name.clone(),
                );

                if let Some(tls_opt) = &self.opts.tls {
                    stream = transport::tls::wrap_stream(stream, tls_opt.to_owned()).await?;
                }

                ws_builder.proxy_stream(stream).await?
            }
            Some(VmessTransport::H2(ref opt)) => {
                let mut tls_opt = self
                    .opts
                    .tls
                    .as_ref()
                    .expect("H2 conn must have tls opt")
                    .clone();
                tls_opt.alpn = Some(vec!["h2".to_string()]);
                stream = transport::tls::wrap_stream(stream, tls_opt.to_owned()).await?;

                let h2_builder = Http2Config {
                    hosts: vec![self.opts.server.clone()],
                    method: http::Method::GET,
                    headers: HashMap::new(),
                    path: opt.path.to_owned().try_into().expect("invalid H2 path"),
                };

                h2_builder.proxy_stream(stream).await?
            }
            Some(VmessTransport::Grpc(ref opt)) => {
                let tls_opt = self.opts.tls.as_ref().expect("gRPC conn must have tls opt");
                stream = transport::tls::wrap_stream(stream, tls_opt.to_owned()).await?;
                let grpc_builder = transport::GrpcStreamBuilder::new(
                    self.opts.server.clone(),
                    opt.service_name
                        .to_owned()
                        .try_into()
                        .expect("invalid gRPC service path"),
                );
                grpc_builder.proxy_stream(stream).await?
            }
            Some(VmessTransport::Http(_)) => {
                unimplemented!("HTTP transport is not implemented yet")
            }
            None => {
                if let Some(tls_opt) = self.opts.tls.as_ref() {
                    stream = transport::tls::wrap_stream(stream, tls_opt.to_owned()).await?;
                }
                stream
            }
        };

        let vmess_builder = vmess_impl::Builder::new(&vmess_impl::VmessOption {
            uuid: self.opts.uuid.to_owned(),
            alter_id: self.opts.alter_id,
            security: self.opts.security.to_owned(),
            udp,
            dst: sess.destination.clone(),
        })?;

        vmess_builder.proxy_stream(underlying).await
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    /// The protocol of the outbound handler
    fn proto(&self) -> OutboundType {
        OutboundType::Vmess
    }

    /// The proxy remote address
    async fn remote_addr(&self) -> Option<SocksAddr> {
        Some(SocksAddr::Domain(self.opts.server.clone(), self.opts.port))
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        let stream = new_tcp_stream(
            resolver,
            self.opts.server.as_str(),
            self.opts.port,
            self.opts.common_opts.iface.as_ref(),
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

        self.inner_proxy_stream(stream, sess, false).await
    }

    /// wraps a stream with outbound handler
    async fn proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        _: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        self.inner_proxy_stream(s, sess, false).await
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

        let remote_addr = resolver
            .resolve_v4(sess.destination.host().as_str())
            .map_err(map_io_error)
            .await?
            .ok_or(new_io_error(
                format!("failed to resolve {}", sess.destination.host()).as_str(),
            ))?;

        let stream = self.inner_proxy_stream(stream, sess, true).await?;

        Ok(Box::new(OutboundDatagramVmess::new(
            stream,
            SocksAddr::Ip(std::net::SocketAddr::new(
                IpAddr::V4(remote_addr),
                sess.destination.port(),
            )),
        )) as AnyOutboundDatagram)
        .into()
    }
}
