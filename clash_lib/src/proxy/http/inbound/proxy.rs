use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use futures::{future::BoxFuture, TryFutureExt};

use hyper::{server::conn::Http, Body, Client, Method, Request, Response, Uri};

use tower::Service;
use tracing::{instrument, warn};

use crate::{
    app::dispatcher::Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    proxy::{AnyStream, ProxyError},
    session::{Network, Session, SocksAddr, Type},
};

use super::{auth::authenticate_req, connector::Connector};

pub fn maybe_socks_addr(r: &Uri) -> Option<SocksAddr> {
    let port = r
        .port_u16()
        .unwrap_or(match r.scheme().map(|s| s.as_str()).unwrap_or_default() {
            "http" => 80 as _,
            "https" => 443 as _,
            _ => return None,
        });

    r.host().map(|x| {
        if let Ok(ip) = x.parse::<IpAddr>() {
            SocksAddr::Ip((ip, port).into())
        } else {
            SocksAddr::Domain(x.to_string(), port)
        }
    })
}

async fn proxy(
    req: Request<Body>,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Result<Response<Body>, ProxyError> {
    if authenticator.enabled() {
        if let Some(res) = authenticate_req(&req, authenticator) {
            return Ok(res);
        }
    }

    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build(Connector::new(src, dispatcher.clone()));

    // TODO: handle other upgrades: https://github.com/hyperium/hyper/blob/master/examples/upgrades.rs
    if req.method() == Method::CONNECT {
        if let Some(addr) = maybe_socks_addr(req.uri()) {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let sess = Session {
                            network: Network::Tcp,
                            typ: Type::HttpConnect,
                            source: src,
                            destination: addr,

                            ..Default::default()
                        };

                        dispatcher.dispatch_stream(sess, upgraded).await
                    }
                    Err(e) => warn!("HTTP handshake failure, {}", e),
                }
            });

            Ok(Response::new(Body::empty()))
        } else {
            Ok(Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(format!("invalid request uri: {}", req.uri()).into())
                .unwrap())
        }
    } else {
        match client
            .request(req)
            .map_err(|x| ProxyError::General(x.to_string()))
            .await
        {
            Ok(res) => Ok(res),
            Err(e) => {
                warn!("http proxy error: {}", e);
                Ok(Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .body(Body::empty())
                    .unwrap())
            }
        }
    }
}

struct ProxyService {
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
}

impl Service<Request<Body>> for ProxyService {
    type Response = Response<Body>;

    type Error = ProxyError;

    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        Box::pin(proxy(
            req,
            self.src,
            self.dispatcher.clone(),
            self.authenticator.clone(),
        ))
    }
}

#[instrument(skip(stream, dispatcher, authenticator))]
pub async fn handle(
    stream: AnyStream,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) {
    tokio::task::spawn(async move {
        if let Err(http_err) = Http::new()
            .http1_only(true)
            .http1_keep_alive(true)
            .serve_connection(
                stream,
                ProxyService {
                    src,
                    dispatcher,
                    authenticator,
                },
            )
            .with_upgrades()
            .await
        {
            warn!("Error while serving HTTP connection: {}", http_err);
        }
    });
}
