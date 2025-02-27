mod grpc;
mod h2;
mod shadow_tls;
mod simple_obfs;
mod sip003;
mod tls;
mod v2ray;
mod ws;

pub use grpc::Client as GrpcClient;
pub use h2::Client as H2Client;
pub use shadow_tls::Client as Shadowtls;
pub use simple_obfs::*;
pub use sip003::Plugin as Sip003Plugin;
pub use tls::Client as TlsClient;
pub use v2ray::{V2RayOBFSOption, V2rayWsClient};
pub use ws::Client as WsClient;

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn proxy_stream(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<super::AnyStream>;
}
