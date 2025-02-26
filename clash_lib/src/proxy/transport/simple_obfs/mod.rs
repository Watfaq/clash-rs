mod http;
mod tls;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SimpleOBFSMode {
    Http,
    Tls,
}

pub struct SimpleOBFSOption {
    pub mode: SimpleOBFSMode,
    pub host: String,
}

#[deprecated(
    since = "0.1.0",
    note = "should be removed since v2ray-plugin is widely used"
)]
pub use http::Client as SimpleObfsHttp;
pub use tls::Client as SimpleObfsTLS;
