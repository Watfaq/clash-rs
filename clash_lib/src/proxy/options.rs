use std::collections::HashMap;

#[allow(dead_code)]
pub struct HttpOption {
    pub method: String,
    pub path: Vec<String>,
    pub headers: HashMap<String, String>,
}

pub struct Http2Option {
    pub host: Vec<String>,
    pub path: String,
}

pub struct GrpcOption {
    pub host: String,
    pub service_name: String,
}

pub struct WsOption {
    pub path: String,
    pub headers: HashMap<String, String>,
    pub max_early_data: usize,
    pub early_data_header_name: String,
}
