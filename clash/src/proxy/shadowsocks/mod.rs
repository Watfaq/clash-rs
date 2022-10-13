mod stream;

use crate::proxy::shadowsocks::stream::HandlerOptions;
use crate::proxy::{AnyStream, CommonOption, OutboundHandler};
use crate::session::Session;
use crate::ThreadSafeDNSResolver;
use std::collections::HashMap;
use stream::handle as stream_handler;

pub struct SimpleOBFSOption {
    pub mode: String,
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

impl OutboundHandler for Handler {
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<AnyStream> {
        stream_handler(sess, &self.opts, resolver).await
    }
}
