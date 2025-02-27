mod grpc;
mod h2;
#[path = "tls.rs"]
mod internal_tls;
mod shadow_tls;
mod simple_obfs;
mod sip003;
mod v2ray;
mod ws;

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn proxy_stream(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<super::AnyStream>;
}

pub use ws::Client as WsClient;

pub use grpc::Client as GrpcClient;
pub use h2::Client as H2Client;

pub mod tls {
    pub use super::internal_tls::wrap_stream;
}
pub use internal_tls::TLSOptions;

pub use shadow_tls::{Client as ShadowtlsPlugin, ShadowTlsOption};
pub use simple_obfs::*;
pub use sip003::Plugin as Sip003Plugin;
pub use v2ray::{V2RayOBFSOption, V2rayWsClient};
