use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::Bytes;
use futures::{future::BoxFuture, StreamExt, TryFutureExt};

use http_body_util::{
    combinators::BoxBody, BodyDataStream, BodyExt, Either, Empty, Full, StreamBody,
};
use hyper::{
    body::{Body, Incoming},
    server::conn::http1,
    Method, Request, Response, Uri,
};

use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tower::Service;
use tracing::{instrument, warn};

use crate::{
    app::dispatcher::Dispatcher,
    common::{
        auth::ThreadSafeAuthenticator,
        errors::map_io_error,
        http::{hyper::TokioIo, HyperResponseBody},
    },
    proxy::{AnyStream, ProxyError},
    session::{Network, Session, SocksAddr, Type},
};

use super::{auth::authenticate_req, connector::Connector};

pub fn maybe_socks_addr(r: &Uri) -> Option<SocksAddr> {
    let port = r.port_u16().unwrap_or(
        match r.scheme().map(|s| s.as_str()).unwrap_or("http") {
            "http" => 80 as _,
            "https" => 443 as _,
            _ => return None,
        },
    );

    r.host().map(|x| {
        if let Ok(ip) = x.parse::<IpAddr>() {
            SocksAddr::Ip((ip, port).into())
        } else {
            SocksAddr::Domain(x.to_string(), port)
        }
    })
}

async fn proxy(
    req: Request<hyper::body::Incoming>,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> Result<Response<HyperResponseBody>, ProxyError> {
    if authenticator.enabled() {
        if let Some(res) = authenticate_req(&req, authenticator) {
            return Ok(res);
        }
    }

    let client = Client::builder(TokioExecutor::new())
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

                        dispatcher
                            .dispatch_stream(sess, TokioIo::new(upgraded))
                            .await
                    }
                    Err(e) => warn!("HTTP handshake failure, {}", e),
                }
            });

            Ok(Response::new(Empty::new().map_err(map_io_error).boxed()))
        } else {
            Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(
                    Full::new(format!("invalid request uri: {}", req.uri()).into())
                        .map_err(map_io_error)
                        .boxed(),
                )
                .unwrap())
        }
    } else {
        match client
            .request(req)
            .map_err(|x| ProxyError::General(x.to_string()))
            .await
        {
            Ok(res) => Ok(res.map(|b| b.map_err(map_io_error).boxed())),
            Err(e) => {
                warn!("http proxy error: {}", e);
                Ok(Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .body(Empty::new().map_err(map_io_error).boxed())
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

impl hyper::service::Service<Request<hyper::body::Incoming>> for ProxyService {
    type Error = ProxyError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    type Response = Response<HyperResponseBody>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
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
        if let Err(http_err) = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
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
