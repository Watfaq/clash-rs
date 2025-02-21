use std::io;

use crate::proxy::{
    AnyStream,
    transport::{self, TLSOptions},
};

use super::V2RayOBFSOption;

pub(crate) mod mux;

pub async fn new_websocket_stream(
    mut stream: AnyStream,
    server: String,
    port: u16,
    opt: &V2RayOBFSOption,
) -> std::io::Result<AnyStream> {
    // this shall already be checked in the config parser
    if opt.mode != "websocket" {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("invalid obfs mode: {}", opt.mode),
        ));
    }

    if opt.mux {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "v2ray plugin does not support mux",
        ));
    }

    let mut headers = opt.headers.clone();
    if !headers.contains_key("Host") {
        headers.insert("Host".to_owned(), opt.host.clone());
    }
    let ws_builder = transport::WebsocketStreamBuilder::new(
        server,
        port,
        if opt.path.is_empty() {
            "/".to_owned()
        } else {
            opt.path.clone()
        },
        headers,
        None,
        0,
        "".to_owned(),
    );

    if opt.tls {
        stream = transport::tls::wrap_stream(
            stream,
            TLSOptions {
                sni: opt.host.clone(),
                skip_cert_verify: opt.skip_cert_verify,
                alpn: Some(vec!["http/1.1".to_owned()]),
            },
            None,
        )
        .await?;
    }

    ws_builder.proxy_stream(stream).await
}
