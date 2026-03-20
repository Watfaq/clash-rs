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
