use std::{collections::HashMap, io, net::IpAddr, sync::Arc};

use async_trait::async_trait;
use futures::TryFutureExt;
use tracing::debug;

mod vmess_impl;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram, ChainedDatagramWrapper,
            ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::{map_io_error, new_io_error},
    session::{Session, SocksAddr},
};

use self::vmess_impl::OutboundDatagramVmess;

use super::{
    options::{GrpcOption, Http2Option, HttpOption, WsOption},
    transport::{self, Http2Config},
    utils::new_tcp_stream,
    AnyOutboundHandler, AnyStream, CommonOption, OutboundHandler, OutboundType,
};

pub enum VmessTransport {
    Ws(WsOption),
    H2(Http2Option),
    Grpc(GrpcOption),
    #[allow(dead_code)]
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
    #[allow(clippy::new_ret_no_self)]
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
                let ws_builder = transport::WebsocketStreamBuilder::new(
                    self.opts.server.clone(),
                    self.opts.port,
                    opt.path.clone(),
                    opt.headers.clone(),
                    None,
                    opt.max_early_data,
                    opt.early_data_header_name.clone(),
                );

                if let Some(tls_opt) = &self.opts.tls {
                    stream = transport::tls::wrap_stream(stream, tls_opt.to_owned(), None).await?;
                }

                ws_builder.proxy_stream(stream).await?
            }
            Some(VmessTransport::H2(ref opt)) => {
                stream = match self.opts.tls.as_ref() {
                    Some(tls_opt) => {
                        let mut tls_opt = tls_opt.clone();
                        tls_opt.alpn = Some(vec!["h2".to_string()]);
                        transport::tls::wrap_stream(stream, tls_opt.to_owned(), None).await?
                    }
                    None => stream,
                };

                let h2_builder = Http2Config {
                    hosts: opt.host.clone(),
                    method: http::Method::GET,
                    headers: HashMap::new(),
                    path: opt.path.to_owned().try_into().expect("invalid H2 path"),
                };

                h2_builder.proxy_stream(stream).await?
            }
            Some(VmessTransport::Grpc(ref opt)) => {
                stream = match self.opts.tls.as_ref() {
                    Some(tls_opt) => {
                        transport::tls::wrap_stream(stream, tls_opt.to_owned(), None).await?
                    }
                    None => stream,
                };

                let grpc_builder = transport::GrpcStreamBuilder::new(
                    opt.host.clone(),
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
                    stream = transport::tls::wrap_stream(stream, tls_opt.to_owned(), None).await?;
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
    ) -> io::Result<BoxedChainedStream> {
        debug!("Connecting to {} via VMess", sess);
        let stream = new_tcp_stream(
            resolver,
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

        let s = self.inner_proxy_stream(stream, sess, false).await?;
        let chained = ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
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

        let remote_addr = resolver
            .resolve_v4(sess.destination.host().as_str(), false)
            .map_err(map_io_error)
            .await?
            .ok_or(new_io_error(
                format!("failed to resolve {}", sess.destination.host()).as_str(),
            ))?;

        let stream = self.inner_proxy_stream(stream, sess, true).await?;

        let d = OutboundDatagramVmess::new(
            stream,
            SocksAddr::Ip(std::net::SocketAddr::new(
                IpAddr::V4(remote_addr),
                sess.destination.port(),
            )),
        );

        let chained = ChainedDatagramWrapper::new(d);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }
}

#[cfg(all(test, not(ci)))]
mod tests {
    use crate::proxy::utils::test_utils::{
        config_helper::test_config_base_dir,
        consts::*,
        docker_runner::{DockerTestRunner, DockerTestRunnerBuilder},
        run_default_test_suites_and_cleanup,
    };

    use super::*;

    async fn get_ws_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let vmess_ws_conf = test_config_dir.join("vmess-ws.json");

        DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .mounts(&[(vmess_ws_conf.to_str().unwrap(), "/etc/v2ray/config.json")])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_vmess_ws() -> anyhow::Result<()> {
        let _ = tracing_subscriber::fmt()
            // any additional configuration of the subscriber you might want here..
            .try_init();

        let span = tracing::info_span!("test_vmess_ws");
        let _enter = span.enter();

        let opts = HandlerOptions {
            name: "test-vmess-ws".into(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.into(),
            port: 10002,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            alter_id: 0,
            security: "none".into(),
            udp: true,
            tls: None,
            transport: Some(VmessTransport::Ws(WsOption {
                path: "".to_owned(),
                headers: [("Host".to_owned(), "example.org".to_owned())]
                    .into_iter()
                    .collect::<HashMap<_, _>>(),
                // ignore the rest by setting max_early_data to 0
                max_early_data: 0,
                early_data_header_name: "".to_owned(),
            })),
        };
        let handler = Handler::new(opts);
        run_default_test_suites_and_cleanup(handler, get_ws_runner().await?).await
    }

    async fn get_grpc_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let conf = test_config_dir.join("vmess-grpc.json");
        let cert = test_config_dir.join("example.org.pem");
        let key = test_config_dir.join("example.org-key.pem");

        DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .mounts(&[
                (conf.to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_vmess_grpc() -> anyhow::Result<()> {
        let opts = HandlerOptions {
            name: "test-vmess-grpc".into(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.into(),
            port: 10002,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            alter_id: 0,
            security: "auto".into(),
            udp: true,
            tls: Some(transport::TLSOptions {
                skip_cert_verify: true,
                sni: "example.org".into(),
                alpn: None,
            }),
            transport: Some(VmessTransport::Grpc(GrpcOption {
                host: "example.org".to_owned(),
                service_name: "example!".to_owned(),
            })),
        };
        let handler = Handler::new(opts);
        run_default_test_suites_and_cleanup(handler, get_grpc_runner().await?).await
    }

    async fn get_h2_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let conf = test_config_dir.join("vmess-http2.json");
        let cert = test_config_dir.join("example.org.pem");
        let key = test_config_dir.join("example.org-key.pem");

        DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .mounts(&[
                (conf.to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_vmess_h2() -> anyhow::Result<()> {
        let opts = HandlerOptions {
            name: "test-vmess-h2".into(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.into(),
            port: 10002,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            alter_id: 0,
            security: "auto".into(),
            udp: false,
            tls: Some(transport::TLSOptions {
                skip_cert_verify: true,
                sni: "example.org".into(),
                alpn: None,
            }),
            transport: Some(VmessTransport::H2(Http2Option {
                host: vec!["example.org".into()],
                path: "/testlollol".into(),
            })),
        };
        let handler = Handler::new(opts);
        run_default_test_suites_and_cleanup(handler, get_h2_runner().await?).await
    }
}
