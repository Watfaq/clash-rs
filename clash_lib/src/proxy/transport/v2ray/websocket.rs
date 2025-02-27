use std::{collections::HashMap, io};

use async_trait::async_trait;

use crate::proxy::{
    AnyStream,
    transport::{self, Sip003Plugin, TLSOptions},
};

use super::V2RayOBFSOption;

impl TryFrom<V2RayOBFSOption> for WsClient {
    type Error = std::io::Error;

    fn try_from(opt: V2RayOBFSOption) -> Result<Self, Self::Error> {
        if opt.mode != "websocket" {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "v2ray plugin does not support this mode",
            ));
        }
        Ok(Self::new(
            opt.host,
            opt.port,
            opt.path,
            opt.headers,
            opt.tls,
            opt.skip_cert_verify,
            opt.mux,
        ))
    }
}

pub struct WsClient {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub tls: bool,
    pub skip_cert_verify: bool,
    pub mux: bool,
}

// TODO: temporarily untested
impl WsClient {
    pub fn new(
        host: String,
        port: u16,
        path: String,
        headers: HashMap<String, String>,
        tls: bool,
        skip_cert_verify: bool,
        mux: bool,
    ) -> Self {
        Self {
            host,
            port,
            path,
            headers,
            tls,
            skip_cert_verify,
            mux,
        }
    }

    pub async fn new_v2ray_websocket_stream(
        &self,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        if self.mux {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "v2ray plugin does not support mux",
            ));
        }

        let mut headers = self.headers.clone();
        if !headers.contains_key("Host") {
            headers.insert("Host".to_owned(), self.host.clone());
        }
        let ws_builder = transport::WsClient::new(
            self.host.clone(),
            self.port,
            if self.path.is_empty() {
                "/".to_owned()
            } else {
                self.path.clone()
            },
            headers,
            None,
            0,
            "".to_owned(),
        );

        if self.tls {
            stream = transport::tls::wrap_stream(
                stream,
                TLSOptions {
                    sni: self.host.clone(),
                    skip_cert_verify: self.skip_cert_verify,
                    alpn: Some(vec!["http/1.1".to_owned()]),
                },
                None,
            )
            .await?;
        }

        ws_builder.proxy_stream(stream).await
    }
}

#[async_trait]
impl Sip003Plugin for WsClient {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        self.new_v2ray_websocket_stream(stream).await
    }
}
