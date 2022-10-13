mod connector;

use crate::proxy::http::inbound::connector::Connector;
use crate::proxy::{InboundListener, ProxyError};
use crate::session::{Network, Session, SocksAddr};
use crate::{Dispatcher, NatManager};
use async_trait::async_trait;
use futures::{FutureExt, TryFutureExt};
use hyper::http::uri::Scheme;
use hyper::server::conn::{AddrStream, Http};
use hyper::service::make_service_fn;
use hyper::{http, Body, Client, Method, Request, Response, Server, Uri};
use log::error;
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::Arc;
use tower::service_fn;
use url::Url;

fn map_error(x: hyper::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, x.to_string())
}

fn maybe_socks_addr(r: &Uri) -> Option<SocksAddr> {
    let port = r
        .port_u16()
        .unwrap_or(match r.scheme().unwrap_or(&Scheme::HTTP) {
            s if s == &Scheme::HTTP => 80 as _,
            s if s == &Scheme::HTTPS => 443 as _,
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

#[derive(Clone)]
pub struct Listener {
    addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
}

impl Listener {
    async fn proxy(
        req: Request<Body>,
        client: Client<Connector>,
        src: SocketAddr,
        dispatcher: Arc<Dispatcher>,
    ) -> Result<Response<Body>, ProxyError> {
        if req.method() == Method::CONNECT {
            if let Some(addr) = maybe_socks_addr(req.uri()) {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            let sess = Session {
                                network: Network::Tcp,
                                source: src,
                                destination: addr,

                                ..Default::default()
                            };

                            dispatcher
                                .dispatch_stream(sess, Box::new(upgraded) as _)
                                .await
                        }
                        Err(e) => error!("socks5 handshake failure"),
                    }
                });

                Ok(Response::new(Body::empty()))
            } else {
                let mut resp = Response::new(Body::from(format!(
                    "invalid request uri: {}",
                    req.uri().to_string()
                )));
                *resp.status_mut() = http::StatusCode::BAD_REQUEST;
                Ok(resp)
            }
        } else {
            client
                .request(req)
                .map_err(|x| ProxyError::General(x.to_string()))
                .await
        }
    }
}

#[async_trait]
impl InboundListener for Listener {
    async fn listen_tcp(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr)?;

        let make_service = make_service_fn(move |socket: &AddrStream| {
            let remote_addr = socket.remote_addr();

            let dispatcher = self.dispatcher.clone();

            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let client = Client::builder()
                        .http1_title_case_headers(true)
                        .http1_preserve_header_case(true)
                        .build(Connector::new(remote_addr.clone(), dispatcher.clone()));
                    Listener::proxy(req, client, remote_addr, dispatcher.clone())
                }))
            }
        });

        let server = Server::from_tcp(listener.into())
            .map_err(map_error)?
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .http2_enable_connect_protocol()
            .serve(make_service);

        server.await.map_err(map_error)
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "unsupported"))
    }
}
