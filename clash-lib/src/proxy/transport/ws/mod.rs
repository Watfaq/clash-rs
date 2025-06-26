use async_trait::async_trait;
use http::{Request, StatusCode};
use std::collections::HashMap;
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{handshake::client::generate_key, protocol::WebSocketConfig},
};

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

mod websocket;
mod websocket_early_data;

pub use websocket::WebsocketConn;
pub use websocket_early_data::WebsocketEarlyDataConn;

pub struct Client {
    server: String,
    port: u16,
    path: String,
    headers: HashMap<String, String>,
    ws_config: Option<WebSocketConfig>,
    max_early_data: usize,
    early_data_header_name: String,
}

impl Client {
    pub fn new(
        server: String,
        port: u16,
        path: String,
        headers: HashMap<String, String>,
        ws_config: Option<WebSocketConfig>,
        max_early_data: usize,
        early_data_header_name: String,
    ) -> Self {
        Self {
            server,
            port,
            path,
            headers,
            ws_config,
            max_early_data,
            early_data_header_name,
        }
    }

    fn req(&self) -> Request<()> {
        let mut request = Request::builder()
            .method("GET")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .uri(format!("ws://{}:{}{}", self.server, self.port, self.path));
        for (k, v) in self.headers.iter() {
            request = request.header(k.as_str(), v.as_str());
        }
        if self.max_early_data > 0 {
            // we will replace this field later
            request = request.header(self.early_data_header_name.as_str(), "xxoo");
        }
        request.body(()).unwrap()
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let req = self.req();
        if self.max_early_data > 0 {
            let early_data_conn = WebsocketEarlyDataConn::new(
                stream,
                req,
                self.ws_config,
                self.early_data_header_name.clone(),
                self.max_early_data,
            );
            Ok(Box::new(early_data_conn))
        } else {
            let (stream, resp) =
                client_async_with_config(req, stream, self.ws_config)
                    .await
                    .map_err(map_io_error)?;

            if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid response",
                ));
            }
            Ok(Box::new(WebsocketConn::from_websocket(stream)))
        }
    }
}
