
mod http;
mod tls;

#[deprecated(since = "0.1.0", note = "should be removed since v2ray-plugin is widely used")]
pub use http::HTTPObfs as SimpleObfsHTTP;
