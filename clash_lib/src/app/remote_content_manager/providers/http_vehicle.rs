use super::{ProviderVehicle, ProviderVehicleType};
use crate::common::{
    errors::map_io_error,
    http::{HttpClient, new_http_client},
};

use async_trait::async_trait;

use http_body_util::BodyExt;
use hyper::Uri;
use watfaq_resolver::Resolver;
use watfaq_state::Context;

use std::{io, sync::Arc};

use std::path::{Path, PathBuf};

pub struct Vehicle {
    pub url: Uri,
    pub path: PathBuf,
    http_client: HttpClient,
}

impl Vehicle {
    pub fn new<T: Into<Uri>, P: AsRef<Path>>(
        ctx: Arc<Context>,
        url: T,
        path: P,
        cwd: Option<P>,
        dns_resolver: Arc<Resolver>,
    ) -> Self {
        let client = new_http_client(ctx, dns_resolver)
            .expect("failed to create http client");
        Self {
            url: url.into(),
            path: match cwd {
                Some(cwd) => cwd.as_ref().join(path),
                None => path.as_ref().to_path_buf(),
            },
            http_client: client,
        }
    }
}

#[async_trait]
impl ProviderVehicle for Vehicle {
    async fn read(&self) -> std::io::Result<Vec<u8>> {
        self.http_client
            .get(self.url.clone())
            .await
            .map_err(|x| io::Error::new(io::ErrorKind::Other, x.to_string()))?
            .into_body()
            .collect()
            .await
            .map(|x| x.to_bytes().to_vec())
            .map_err(map_io_error)
    }

    fn path(&self) -> &str {
        self.path.to_str().unwrap()
    }

    fn typ(&self) -> ProviderVehicleType {
        ProviderVehicleType::Http
    }
}
