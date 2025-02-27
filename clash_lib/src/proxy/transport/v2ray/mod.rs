mod websocket;

pub use websocket::V2rayWsClient;

#[allow(dead_code)]
pub struct V2RayOBFSOption {
    /// currently only websocket is supported
    pub mode: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub headers: std::collections::HashMap<String, String>,
    pub tls: bool,
    pub skip_cert_verify: bool,
    pub mux: bool,
}
