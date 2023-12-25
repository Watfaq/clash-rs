use base64::Engine;
use http::{Request, Response};
use hyper::Body;
use tracing::warn;

use crate::common::auth::ThreadSafeAuthenticator;

fn parse_basic_proxy_authorization(req: &Request<Body>) -> Option<&str> {
    req.headers()
        .get(http::header::PROXY_AUTHORIZATION)
        .map(|v| v.to_str().unwrap_or_default())
        .map(|v| {
            if v.starts_with("Basic ") {
                Some(&v[6..])
            } else {
                None
            }
        })
        .and_then(|v| v)
}
fn decode_basic_proxy_authorization(cred: &str) -> Option<(String, String)> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cred)
        .ok()?;
    let s = std::str::from_utf8(&decoded).ok()?;

    let (user, pass) = s.split_once(':')?;
    
    
    Some((user.to_owned(), pass.to_owned()))
}

/// returns a auth required response on auth failure
pub fn authenticate_req(
    req: &Request<Body>,
    authenticator: ThreadSafeAuthenticator,
) -> Option<Response<Body>> {
    let auth_resp = Response::builder()
        .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(http::header::PROXY_AUTHENTICATE, "Basic")
        .body("Proxy Auth Required".into())
        .unwrap();
    let cred = parse_basic_proxy_authorization(req);
    if cred.is_none() {
        return Some(auth_resp);
    }
    let cred = decode_basic_proxy_authorization(cred.unwrap());
    if cred.is_none() {
        return Some(auth_resp);
    }

    let (user, pass) = cred.unwrap();

    if authenticator.authenticate(&user, &pass) {
        None
    } else {
        warn!("proxy authentication failed");
        Some(auth_resp)
    }
}
