use crate::app::ThreadSafeAsyncDnsClient;
use crate::common::providers::{ProviderVehicle, ProviderVehicleType};
use crate::proxy::utils::new_tcp_stream;
use crate::proxy::AnyStream;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use hyper::body::HttpBody;
use hyper::client::connect;
use hyper::client::connect::{Connected, Connection};
use hyper::http::uri::Scheme;
use hyper::service::Service;
use hyper::{body, Uri};
use std::any::Any;
use std::borrow::Borrow;
use std::future::Future;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use url::Url;

#[derive(Clone)]
struct LocalConnector(pub ThreadSafeAsyncDnsClient);

impl Service<Uri> for LocalConnector {
    type Response = AnyStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, remote: Uri) -> Self::Future {
        Box::pin(new_tcp_stream(
            self.0,
            remote
                .host()
                .expect(format!("invalid url: {}", remote.to_string()).as_str()),
            remote.port_u16().unwrap_or(match remote.scheme_str() {
                None => 80,
                Some(s) => match s {
                    s if s == "http" => 80,
                    s if s == "https" => 443,
                    _ => panic!("invalid url: {}", remote),
                },
            }),
            None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            None,
        ))
    }
}

impl Connection for AnyStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

type HttpClient = hyper::Client<LocalConnector>;

pub struct Vehicle {
    pub url: Uri,
    pub path: PathBuf,
    http_client: HttpClient,
}

impl Vehicle {
    pub fn new<T: Into<Uri>, P: AsRef<Path>>(
        url: T,
        path: P,
        dns_resolver: ThreadSafeAsyncDnsClient,
    ) -> Self {
        let connector = LocalConnector(dns_resolver);

        let client = hyper::Client::builder().build::<_, hyper::Body>(connector);
        Self {
            url: url.into(),
            path: path.as_ref().to_path_buf(),
            http_client: client,
        }
    }
}

fn map_hyper_error(x: hyper::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, x.to_string())
}

#[async_trait]
impl ProviderVehicle for Vehicle {
    async fn read(&self) -> std::io::Result<Vec<u8>> {
        body::to_bytes(
            self.http_client
                .get(self.url.into())
                .await
                .map_err(|x| io::Error::new(io::ErrorKind::Other, x.to_string()))?,
        )
        .await
        .map_err(map_hyper_error)
        .map(|x| x.into_iter().collect::<Vec<u8>>())
    }

    fn path(&self) -> &str {
        todo!()
    }

    fn typ(&self) -> ProviderVehicleType {
        todo!()
    }
}
