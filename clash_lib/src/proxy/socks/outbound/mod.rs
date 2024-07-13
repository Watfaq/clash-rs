mod datagram;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    proxy::{
        transport::{self, TLSOptions},
        utils::{new_tcp_stream, new_udp_socket, RemoteConnector},
        AnyOutboundHandler, AnyStream, CommonOption, ConnectorType, OutboundHandler,
        OutboundType,
    },
    session::Session,
};

use async_trait::async_trait;
use datagram::Socks5Datagram;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::debug;

use super::socks5::{client_handshake, socks_command};

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: CommonOption,
    pub server: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub udp: bool,
    pub tls: bool,
    pub sni: String,
    pub skip_cert_verify: bool,
}

pub struct Handler {
    opts: HandlerOptions,
}

impl Handler {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(opts: HandlerOptions) -> AnyOutboundHandler {
        Arc::new(Self { opts })
    }

    async fn inner_connect_stream(
        &self,
        s: AnyStream,
        sess: &Session,
    ) -> std::io::Result<AnyStream> {
        let mut s = if self.opts.tls {
            let tls_opt = TLSOptions {
                skip_cert_verify: self.opts.skip_cert_verify,
                sni: self.opts.sni.clone(),
                alpn: None,
            };

            transport::tls::wrap_stream(s, tls_opt, None).await?
        } else {
            s
        };

        client_handshake(
            &mut s,
            &sess.destination,
            socks_command::CONNECT,
            self.opts.user.clone(),
            self.opts.password.clone(),
        )
        .await?;

        Ok(s)
    }

    async fn inner_connect_datagram(
        &self,
        s: AnyStream,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<Socks5Datagram> {
        let mut s = if self.opts.tls {
            let tls_opt = TLSOptions {
                skip_cert_verify: self.opts.skip_cert_verify,
                sni: self.opts.sni.clone(),
                alpn: None,
            };

            transport::tls::wrap_stream(s, tls_opt, None).await?
        } else {
            s
        };

        let bind_addr = client_handshake(
            &mut s,
            &sess.destination,
            socks_command::CONNECT,
            self.opts.user.clone(),
            self.opts.password.clone(),
        )
        .await?;

        let bind_ip = bind_addr
            .ip()
            .ok_or(new_io_error("missing IP in bind address"))?;
        let bind_ip = if bind_ip.is_unspecified() {
            let remote_addr = resolver
                .resolve(&self.opts.server, false)
                .await
                .map_err(|x| new_io_error(x.to_string().as_str()))?;
            remote_addr.ok_or(new_io_error(
                "no bind addr returned from server and failed to resolve server \
                 address",
            ))?
        } else {
            bind_ip
        };
        let bind_port = bind_addr.port();

        let udp_socket = new_udp_socket(
            None,
            self.opts.common_opts.iface.as_ref().or(sess.iface.as_ref()),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        )
        .await?;

        tokio::spawn(async move {
            loop {
                let mut buf = vec![0u8; 2 * 1024];
                match s.read(&mut buf).await {
                    Ok(_) => {
                        continue;
                    }

                    Err(e) => {
                        // TODO: maybe we should drop the UdpSocket somehow?
                        // these's no close() method on UdpSocket
                        debug!("UDP association closed: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(Socks5Datagram::new((bind_ip, bind_port).into(), udp_socket))
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Socks5
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let s = new_tcp_stream(
            resolver,
            self.opts.server.as_str(),
            self.opts.port,
            self.opts.common_opts.iface.as_ref().or(sess.iface.as_ref()),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        )
        .await?;

        let s = self.inner_connect_stream(s, sess).await?;

        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let s = new_tcp_stream(
            resolver.clone(),
            self.opts.server.as_str(),
            self.opts.port,
            self.opts.common_opts.iface.as_ref().or(sess.iface.as_ref()),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        )
        .await?;

        let d = self.inner_connect_datagram(s, sess, resolver).await?;

        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;

        Ok(Box::new(d))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedStream> {
        let s = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                self.opts.common_opts.iface.as_ref().or(sess.iface.as_ref()),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                None,
            )
            .await?;

        let s = self.inner_connect_stream(s, sess).await?;

        let s = ChainedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedChainedDatagram> {
        let s = connector
            .connect_stream(
                resolver.clone(),
                self.opts.server.as_str(),
                self.opts.port,
                self.opts.common_opts.iface.as_ref().or(sess.iface.as_ref()),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                None,
            )
            .await?;

        let d = self.inner_connect_datagram(s, sess, resolver).await?;

        let d = ChainedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }
}
