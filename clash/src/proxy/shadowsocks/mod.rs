mod datagram;
mod obfs;

use async_trait::async_trait;
use futures::TryFutureExt;
use shadowsocks::{
    config::ServerType, context::Context, crypto::CipherKind,
    relay::udprelay::proxy_socket::UdpSocketType, ProxyClientStream, ProxySocket, ServerConfig,
};

use crate::{
    app::ThreadSafeDNSResolver,
    proxy::{CommonOption, OutboundHandler},
    session::Session,
    Error,
};
use std::{collections::HashMap, io, sync::Arc};

use self::datagram::OutboundDatagramShadowsocks;

use super::{
    utils::{new_tcp_stream, new_udp_socket},
    AnyOutboundDatagram, AnyOutboundHandler, AnyStream,
};

pub enum SimpleOBFSMode {
    Http,
    Tls,
}

pub struct SimpleOBFSOption {
    pub mode: SimpleOBFSMode,
    pub host: String,
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for SimpleOBFSOption {
    type Error = crate::Error;

    fn try_from(value: HashMap<String, serde_yaml::Value>) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

        match mode {
            "http" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Http,
                host: host.to_owned(),
            }),
            "tls" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Tls,
                host: host.to_owned(),
            }),
            _ => Err(Error::InvalidConfig(format!("invalid obfs mode: {}", mode))),
        }
    }
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

impl TryFrom<HashMap<String, serde_yaml::Value>> for V2RayOBFSOption {
    type Error = crate::Error;

    fn try_from(value: HashMap<String, serde_yaml::Value>) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

        if mode != "websocket" {
            return Err(Error::InvalidConfig(format!("invalid obfs mode: {}", mode)));
        }

        let path = value
            .get("path")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs path is required".to_owned()))?;
        let mux = value.get("mux").and_then(|x| x.as_bool()).unwrap_or(false);
        let tls = value.get("tls").and_then(|x| x.as_bool()).unwrap_or(false);
        let skip_cert_verify = value
            .get("skip-cert-verify")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);

        let mut headers = HashMap::new();
        if let Some(h) = value.get("headers") {
            if let Some(h) = h.as_mapping() {
                for (k, v) in h {
                    if let (Some(k), Some(v)) = (k.as_str(), v.as_str()) {
                        headers.insert(k.to_owned(), v.to_owned());
                    }
                }
            }
        }

        Ok(V2RayOBFSOption {
            mode: mode.to_owned(),
            host: host.to_owned(),
            path: path.to_owned(),
            tls,
            headers,
            skip_cert_verify,
            mux,
        })
    }
}

pub enum OBFSOption {
    Simple(SimpleOBFSOption),
    V2Ray(V2RayOBFSOption),
}

pub struct HandlerOptions {
    pub name: String,
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

impl Handler {
    pub fn new(opts: HandlerOptions) -> AnyOutboundHandler {
        Arc::new(Self { opts })
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        self.opts.name.as_str()
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

        if let Some(plugin) = &self.opts.plugin_opts {
            match plugin {
                OBFSOption::Simple(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "simple-obfs is deprecated, please use v2ray-plugin instead",
                    ))
                }
                OBFSOption::V2Ray(opt) => {
                    let mut stream = v2ray::V2RayStream::new(stream, opt.clone());
                    stream.connect().await?;
                    Ok(Box::new(stream))
                }
            }
        }

        let ctx = Context::new_shared(ServerType::Local);
        let cfg = ServerConfig::new(
            (self.opts.server.to_owned(), self.opts.port),
            self.opts.password.to_owned(),
            match self.opts.cipher.as_str() {
                "aes-128-gcm" => CipherKind::AES_128_GCM,
                "aes-256-gcm" => CipherKind::AES_256_GCM,
                "chacha20-ietf-poly1305" => CipherKind::CHACHA20_POLY1305,
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
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyOutboundDatagram> {
        let ctx = Context::new_shared(ServerType::Local);
        let cfg = ServerConfig::new(
            (self.opts.server.to_owned(), self.opts.port),
            self.opts.password.to_owned(),
            match self.opts.cipher.as_str() {
                "aes-128-gcm" => CipherKind::AES_128_GCM,
                "aes-256-gcm" => CipherKind::AES_256_GCM,
                "chacha20-ietf-poly1305" => CipherKind::CHACHA20_POLY1305,
                _ => return Err(io::Error::new(io::ErrorKind::Other, "unsupported cipher")),
            },
        );
        let socket = new_udp_socket(None, self.opts.common_opts.iface.as_ref()).await?;
        let socket = ProxySocket::from_socket(UdpSocketType::Client, ctx, &cfg, socket);
        Ok(OutboundDatagramShadowsocks::new(
            socket,
            (self.opts.server.to_owned(), self.opts.port),
            resolver,
        )
        .into())
    }
}
