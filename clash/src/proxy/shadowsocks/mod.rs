mod obfs;
mod outbound;
mod stream;

use async_trait::async_trait;
use shadowsocks::{
    config::ServerType, context::Context, ProxyClientStream, ProxySocket, ServerConfig,
};

use crate::{
    app::ThreadSafeDNSResolver,
    proxy::{CommonOption, OutboundHandler},
    session::Session,
};
use std::{collections::HashMap, io};

use self::outbound::OutboundDatagramShadowsocks;

use super::{
    utils::{new_tcp_stream, new_udp_socket},
    AnyOutboundDatagram, AnyStream,
};

enum SimpleOBFSMode {
    Http,
    Tls,
}

pub struct SimpleOBFSOption {
    pub mode: SimpleOBFSMode,
    pub host: String,
}

pub struct V2RayOBFSOption {
    pub mode: String,
    pub host: String,
    pub path: String,
    pub tls: bool,
    pub headers: HashMap<String, String>,
    pub skip_cert_verify: bool,
    pub mux: bool,
}

pub enum OBFSOption {
    Simple(SimpleOBFSOption),
    V2Ray(V2RayOBFSOption),
}

pub struct HandlerOptions {
    pub common_opts: CommonOption,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub plugin_opts: Option<OBFSOption>,
}

pub struct Handler {
    opts: HandlerOptions,
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        "ss"
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream> {
        if self.opts.plugin_opts.is_some() {
            unimplemented!("plugin is not supported yet");
        }

        let stream = new_tcp_stream(
            resolver,
            self.opts.server.as_str(),
            self.opts.port,
            self.opts.common_opts.iface.as_ref(),
        )
        .await?;

        let ctx = Context::new_shared(ServerType::Local);
        let cfg = ServerConfig::new(
            (self.opts.server.to_owned(), self.opts.port),
            self.opts.password.to_owned(),
            match self.opts.cipher.as_str() {
                "aes-128-gcm" => shadowsocks::crypto::v1::CipherKind::AES_128_GCM,
                "aes-256-gcm" => shadowsocks::crypto::v1::CipherKind::AES_256_GCM,
                "chacha20-ietf-poly1305" => shadowsocks::crypto::v1::CipherKind::CHACHA20_POLY1305,
                _ => return Err(io::Error::new(io::ErrorKind::Other, "unsupported cipher")),
            },
        );

        let stream = ProxyClientStream::from_stream(
            ctx,
            stream,
            &cfg,
            (sess.destination.host(), sess.destination.port()),
        );

        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        #[allow(unused_variables)] sess: &Session,
        #[allow(unused_variables)] resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        let ctx = Context::new_shared(ServerType::Local);
        let cfg = ServerConfig::new(
            (self.opts.server.to_owned(), self.opts.port),
            self.opts.password.to_owned(),
            match self.opts.cipher.as_str() {
                "aes-128-gcm" => shadowsocks::crypto::v1::CipherKind::AES_128_GCM,
                "aes-256-gcm" => shadowsocks::crypto::v1::CipherKind::AES_256_GCM,
                "chacha20-ietf-poly1305" => shadowsocks::crypto::v1::CipherKind::CHACHA20_POLY1305,
                _ => return Err(io::Error::new(io::ErrorKind::Other, "unsupported cipher")),
            },
        );
        let socket = new_udp_socket(None, self.opts.common_opts.iface.as_ref()).await?;
        let socket = ProxySocket::from_socket(ctx, &cfg, socket);
        Ok(
            OutboundDatagramShadowsocks::new(socket, (self.opts.server.to_owned(), self.opts.port))
                .into(),
        )
    }
}
