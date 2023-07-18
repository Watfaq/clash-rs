mod grpc;
mod h2;
#[path = "tls.rs"]
mod internal_tls;
mod websocket;

pub use websocket::WebsocketConn;
pub use websocket::WebsocketEarlyDataConn;
pub use websocket::WebsocketStreamBuilder;

pub use grpc::GrpcStream;
pub use grpc::GrpcStreamBuilder;

pub use self::h2::Http2Config;

pub mod tls {
    pub use super::internal_tls::wrap_stream;
}
pub use internal_tls::TLSOptions;
