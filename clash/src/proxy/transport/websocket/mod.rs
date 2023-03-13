mod websocket;
mod websocket_early_data;

use std::collections::HashMap;

use http::{Request, StatusCode, Uri};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{handshake::client::generate_key, protocol::WebSocketConfig},
};
pub use websocket::WebsocketConn;
pub use websocket_early_data::WebsocketEarlyDataConn;

use crate::{common::errors::map_io_error, proxy::AnyStream};

pub struct WebsocketStreamBuilder {
    uri: Uri,
    headers: HashMap<String, String>,
    ws_config: Option<WebSocketConfig>,
    max_early_data: usize,
    early_data_header_name: String,
}

impl WebsocketStreamBuilder {
    pub fn new(
        uri: Uri,
        headers: HashMap<String, String>,
        ws_config: Option<WebSocketConfig>,
        max_early_data: usize,
        early_data_header_name: String,
    ) -> Self {
        Self {
            uri,
            headers,
            ws_config,
            max_early_data,
            early_data_header_name,
        }
    }

    fn req(&self) -> Request<()> {
        let authority = self.uri.authority().unwrap().as_str();
        let host = authority
            .find('@')
            .map(|idx| authority.split_at(idx + 1).1)
            .unwrap_or_else(|| authority);
        let mut request = Request::builder()
            .method("GET")
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .uri(self.uri.clone());
        for (k, v) in self.headers.iter() {
            if k != "Host" {
                request = request.header(k.as_str(), v.as_str());
            }
        }
        if self.max_early_data > 0 {
            // we will replace this field later
            request = request.header(self.early_data_header_name.as_str(), "s");
        }
        request.body(()).unwrap()
    }

    pub async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let req = self.req();
        if self.max_early_data > 0 {
            let early_data_conn = WebsocketEarlyDataConn::new(
                stream,
                req,
                self.ws_config.clone(),
                self.early_data_header_name.clone(),
                self.max_early_data,
            );
            Ok(Box::new(early_data_conn))
        } else {
            let (stream, resp) = client_async_with_config(req, stream, self.ws_config)
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
