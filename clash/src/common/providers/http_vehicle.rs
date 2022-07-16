use crate::app::ThreadSafeAsyncDnsClient;
use crate::common::providers::{ProviderVehicle, ProviderVehicleType};
use crate::proxy::utils::new_tcp_stream;
use async_trait::async_trait;
use futures::TryFutureExt;
use hyper::service::{service_fn, Service};
use hyper::{body, Uri};
use std::borrow::Borrow;
use std::path::{Path, PathBuf};
use url::Url;

pub struct Vehicle<C> {
    pub url: Url,
    pub path: PathBuf,
    http_client: hyper::Client<C>,
}

impl<C> Vehicle<C>
where
    C: hyper::client::connect::Connect + Clone + Send + Sync,
{
    pub fn new<T: Into<Url>, P: AsRef<Path>>(
        url: T,
        path: P,
        dns_resolver: ThreadSafeAsyncDnsClient,
    ) -> Self {
        let connector = service_fn(|remote: Uri| {
            new_tcp_stream(dns_resolver, remote.host()?, remote.port_u16()?, None, None)
        });
        let client = hyper::Client::builder().build::<_, hyper::Body>(connector);
        Self {
            url,
            path,
            http_client: client,
        }
    }
}

#[async_trait]
impl<C> ProviderVehicle for Vehicle<C>
where
    C: hyper::client::connect::Connect + Clone + Send + Sync,
{
    async fn read(&self) -> std::io::Result<Vec<u8>> {
        body::to_bytes(self.http_client.get(self.url.into()).await?)
    }

    fn path(&self) -> &str {
        todo!()
    }

    fn typ(&self) -> ProviderVehicleType {
        todo!()
    }
}
