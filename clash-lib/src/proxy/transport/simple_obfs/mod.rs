#![allow(dead_code)]

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

pub use http::Client as SimpleObfsHttp;
pub use tls::Client as SimpleObfsTLS;
