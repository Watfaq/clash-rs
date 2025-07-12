use std::{collections::HashMap, io};

use async_trait::async_trait;

use crate::proxy::{
    AnyStream,
    transport::{self, TlsClient, Transport},
};

use super::V2RayOBFSOption;

impl TryFrom<V2RayOBFSOption> for V2rayWsClient {
    type Error = std::io::Error;

    fn try_from(opt: V2RayOBFSOption) -> Result<Self, Self::Error> {
        if opt.mode != "websocket" {
            return Err(io::Error::other("v2ray plugin does not support this mode"));
        }
        Self::try_new(
            opt.host,
            opt.port,
            opt.path,
            opt.headers,
            opt.tls,
            opt.skip_cert_verify,
            opt.mux,
        )
    }
}

pub struct V2rayWsClient {
    pub tls_client: Option<Box<dyn Transport>>,
    pub ws_client: transport::WsClient,
}

// TODO: temporarily untested
impl V2rayWsClient {
    pub fn try_new(
        host: String,
        port: u16,
        path: String,
        mut headers: HashMap<String, String>,
        tls: bool,
        skip_cert_verify: bool,
        mux: bool,
    ) -> std::io::Result<Self> {
        if mux {
            return Err(io::Error::other("v2ray plugin does not support mux"));
        }

        let tls_client = if tls {
            Some(Box::new(TlsClient::new(
                skip_cert_verify,
                host.clone(),
                Some(vec!["http/1.1".to_owned()]),
                None,
            )) as _)
        } else {
            None
        };

        if !headers.contains_key("Host") {
            headers.insert("Host".to_owned(), host.clone());
        }
        let ws_client = transport::WsClient::new(
            host.clone(),
            port,
            if path.is_empty() {
                "/".to_owned()
            } else {
                path.clone()
            },
            headers,
            None,
            0,
            "".to_owned(),
        );

        Ok(Self {
            tls_client,
            ws_client,
        })
    }

    pub async fn new_v2ray_websocket_stream(
        &self,
        s: AnyStream,
    ) -> std::io::Result<AnyStream> {
        let s = if let Some(tls_client) = self.tls_client.as_ref() {
            tls_client.proxy_stream(s).await?
        } else {
            s
        };

        self.ws_client.proxy_stream(s).await
    }
}

#[async_trait]
impl Transport for V2rayWsClient {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        self.new_v2ray_websocket_stream(stream).await
    }
}
