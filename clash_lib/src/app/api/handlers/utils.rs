use http::{HeaderMap, header};
use tracing::trace;

pub fn is_request_websocket(header: HeaderMap) -> bool {
    trace!(
        "Checking if request is a WebSocket upgrade, headers: {:?}",
        header
    );
    header
        .get(header::CONNECTION)
        .and_then(|x| x.to_str().ok().map(|x| x.to_ascii_lowercase()))
        // Firefox sends "Connection: keep-alive, Upgrade"
        .is_some_and(|x| x.contains(&"upgrade".to_ascii_lowercase()))
        && header
            .get(header::UPGRADE)
            .and_then(|x| x.to_str().ok().map(|x| x.to_ascii_lowercase()))
            == Some("websocket".to_ascii_lowercase())
}
