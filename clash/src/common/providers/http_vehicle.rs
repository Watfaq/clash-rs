use crate::app::ThreadSafeDNSResolver;
use crate::common::errors::map_io_error;
use crate::common::providers::{ProviderVehicle, ProviderVehicleType};
use crate::proxy::utils::new_tcp_stream;
use crate::proxy::AnyStream;
use async_trait::async_trait;
use futures::TryFutureExt;
use hyper::body::HttpBody;

use hyper::client::connect::{Connected, Connection};

use hyper::service::Service;
use hyper::{body, Uri};

use std::future::Future;
use std::io;

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Clone)]
struct LocalConnector(pub ThreadSafeDNSResolver);

impl Service<Uri> for LocalConnector {
    type Response = AnyStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, remote: Uri) -> Self::Future {
        let host = remote
            .host()
            .expect(format!("invalid url: {}", remote.to_string()).as_str())
            .to_owned();

        let dns = self.0.clone();

        Box::pin(async move {
            new_tcp_stream(
                dns,
                host.as_str(),
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
            )
            .await
        })
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
        dns_resolver: ThreadSafeDNSResolver,
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

#[async_trait]
impl ProviderVehicle for Vehicle {
    async fn read(&self) -> std::io::Result<Vec<u8>> {
        body::to_bytes(
            self.http_client
                .get(self.url.clone())
                .await
                .map_err(|x| io::Error::new(io::ErrorKind::Other, x.to_string()))?,
        )
        .await
        .map_err(map_io_error)
        .map(|x| x.into_iter().collect::<Vec<u8>>())
    }

    fn path(&self) -> &str {
        self.path.to_str().unwrap()
    }

    fn typ(&self) -> ProviderVehicleType {
        ProviderVehicleType::HTTP
    }
}
