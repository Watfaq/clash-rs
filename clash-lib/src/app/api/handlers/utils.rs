use std::{io, time::Duration};

use http::{HeaderMap, header};
use serde::Deserialize;

use crate::{
    app::outbound::manager::ThreadSafeOutboundManager,
    proxy::AnyOutboundHandler,
};

/// Shared query-string parameters for all latency-test endpoints.
#[derive(Deserialize)]
pub struct DelayRequest {
    pub url: String,
    pub timeout: u16,
}

/// Run `url_test` over a group proxy and all its members, and return
/// the active proxy alongside the results.
///
/// The caller must ensure `proxy.try_as_group_handler()` returns `Some`.
///
/// Returns `(members, results, active_proxy)` where:
/// - `members[i]`   is the i-th member proxy handler.
/// - `results[0]`   is for the group proxy itself.
/// - `results[i+1]` is for `members[i]`.
/// - `active_proxy` is the currently selected proxy for the group (if any).
pub async fn group_url_test(
    outbound_manager: &ThreadSafeOutboundManager,
    proxy: AnyOutboundHandler,
    fallback_url: &str,
    timeout: Duration,
) -> (
    Vec<AnyOutboundHandler>,
    Vec<io::Result<(Duration, Duration)>>,
    Option<AnyOutboundHandler>,
) {
    let group = proxy
        .try_as_group_handler()
        .expect("caller must ensure proxy is a group");
    let latency_test_url = group.get_latency_test_url();
    let members = group.get_proxies().await;
    let active_proxy = group.get_active_proxy().await;
    // `group` is not used after this point; NLL ends the borrow on `proxy`,
    // allowing it to be moved into the url_test call below.
    let results = outbound_manager
        .url_test(
            &[vec![proxy], members.clone()].concat(),
            &latency_test_url.unwrap_or_else(|| fallback_url.to_owned()),
            timeout,
        )
        .await;
    (members, results, active_proxy)
}

pub fn is_request_websocket(header: &HeaderMap) -> bool {
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
