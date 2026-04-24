use std::{io, time::Duration};

use http::{HeaderMap, header};
use serde::Deserialize;

use crate::{
    app::outbound::manager::ThreadSafeOutboundManager, proxy::AnyOutboundHandler,
};

/// Shared query-string parameters for all latency-test endpoints.
#[derive(Deserialize)]
pub struct DelayRequest {
    pub url: String,
    pub timeout: u16,
}

/// Run `url_test` over a group proxy and all its members, and if the group has
/// a latency test URL, use it as the test URL; otherwise, use the provided
/// fallback URL.
/// Returns the latency of the group active proxy if found, otherwise the
/// latency of the group itself.
pub async fn group_url_test(
    outbound_manager: &ThreadSafeOutboundManager,
    proxy: AnyOutboundHandler,
    fallback_url: &str,
    timeout: Duration,
) -> std::io::Result<(Duration, Duration)> {
    let group = proxy
        .try_as_group_handler()
        .expect("caller must ensure proxy is a group");
    let latency_test_url = group.get_latency_test_url();
    let members = group.get_proxies().await;
    let active_proxy = group.get_active_proxy().await;
    let active_idx = active_proxy
        .as_ref()
        .and_then(|active| members.iter().position(|p| p.name() == active.name()));

    let results = outbound_manager
        .url_test(
            &[vec![proxy], members].concat(),
            latency_test_url.as_deref().unwrap_or(fallback_url),
            timeout,
        )
        .await;

    // if found active proxy, return the latency of the active proxy, otherwise
    // return the latency of the first proxy (which is the latency of the group).
    let result = if let Some(idx) = active_idx {
        results
            .get(idx + 1)
            .expect("active proxy index must be within the range of proxies")
    } else {
        results
            .first()
            .expect("there must be at least one proxy in the group")
    };

    match result {
        Ok(latency) => Ok(*latency),
        Err(err) => Err(io::Error::other(err.to_string())),
    }
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
