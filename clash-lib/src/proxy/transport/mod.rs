mod grpc;
mod h2;
mod reality;
#[cfg(feature = "shadowsocks")]
mod shadow_tls;
#[cfg(feature = "shadowsocks")]
mod simple_obfs;
#[cfg(feature = "shadowsocks")]
mod sip003;
pub mod splice_tls;
mod tls;
#[cfg(feature = "shadowsocks")]
mod v2ray;
mod ws;

pub use grpc::Client as GrpcClient;
pub use h2::Client as H2Client;
pub use reality::Client as RealityClient;
#[cfg(feature = "shadowsocks")]
pub use shadow_tls::Client as Shadowtls;
#[cfg(feature = "shadowsocks")]
pub use simple_obfs::{
    SimpleOBFSMode, SimpleOBFSOption, SimpleObfsHttp, SimpleObfsTLS,
};
#[cfg(feature = "shadowsocks")]
pub use sip003::Plugin as Sip003Plugin;
pub use splice_tls::VisionOptions;
pub use tls::Client as TlsClient;
#[cfg(feature = "shadowsocks")]
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
