use std::{collections::HashMap, io};

use http::header::HeaderName;

use crate::{common::errors::map_io_error, proxy::AnyStream};

pub struct Option {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub tls: bool,
    pub skip_cert_verify: bool,
    pub mux: bool,
}

pub(crate) fn wrap_stream(s: AnyStream, opt: Option) -> io::Result<AnyStream> {
    let mut header = http::HeaderMap::new();
    for (k, v) in opt.headers {
        header.insert(
            HeaderName::from_lowercase(k.as_bytes()).map_err(map_io_error)?,
            v.parse().map_err(map_io_error)?,
        );
    }

    

    Ok(s)
}
