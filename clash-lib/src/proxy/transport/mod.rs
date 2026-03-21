#![allow(dead_code)]
#![allow(unused_imports)]

mod grpc;
mod h2;
mod reality;
mod shadow_tls;
mod simple_obfs;
mod sip003;
pub mod splice_tls;
mod tls;
mod v2ray;
mod ws;

pub use grpc::Client as GrpcClient;
pub use h2::Client as H2Client;
pub use reality::Client as RealityClient;
pub use shadow_tls::Client as Shadowtls;
pub use simple_obfs::*;
pub use sip003::Plugin as Sip003Plugin;
pub use splice_tls::VisionOptions;
pub use tls::Client as TlsClient;
pub use v2ray::{V2RayOBFSOption, V2rayWsClient};
pub use ws::Client as WsClient;

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn proxy_stream(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<super::AnyStream>;

    /// Like `proxy_stream`, but additionally returns a `VisionOptions` for
    /// transports that support XTLS-splice (Reality).  The default
    /// implementation delegates to `proxy_stream` and returns `None`,
    /// meaning no splice is available.
    async fn proxy_stream_spliced(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<(super::AnyStream, Option<VisionOptions>)> {
        Ok((self.proxy_stream(stream).await?, None))
    }
}
