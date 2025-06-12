use crate::{Error, common::utils::download};
use prost::Message;
use std::path::Path;
use tracing::{debug, info};

use super::http::HttpClient;

pub(crate) mod geodata_proto {
    include!(concat!(env!("OUT_DIR"), "/geodata.rs"));
}

pub struct GeoData {
    cache: geodata_proto::GeoSiteList,
}

pub type GeoDataLookup = std::sync::Arc<dyn GeoDataLookupTrait + Send + Sync>;

#[cfg_attr(test, mockall::automock)]
pub trait GeoDataLookupTrait {
    fn get(&self, list: &str) -> Option<geodata_proto::GeoSite>;
}

impl GeoDataLookupTrait for GeoData {
    fn get(&self, list: &str) -> Option<geodata_proto::GeoSite> {
        self.cache
            .entry
            .iter()
            .find(|x| x.country_code.eq_ignore_ascii_case(list))
            .cloned()
    }
}

impl GeoData {
    pub async fn new<P: AsRef<Path>>(
        path: P,
        download_url: Option<String>,
        http_client: HttpClient,
    ) -> Result<Self, Error> {
        debug!("geosite path: {}", path.as_ref().to_string_lossy());

        let geosite_file = path.as_ref().to_path_buf();

        if !geosite_file.exists() {
            if let Some(url) = download_url.as_ref() {
                info!("downloading geodata from {}", url);
                download(url, &geosite_file, &http_client)
                    .await
                    .map_err(|x| {
                        Error::InvalidConfig(format!(
                            "geosite download failed: {}",
                            x
                        ))
                    })?;
            } else {
                return Err(Error::InvalidConfig(format!(
                    "geosite `{}` not found and geosite_download_url is not set",
                    path.as_ref().to_string_lossy()
                )));
            }
        }
        let bytes = tokio::fs::read(path).await?;
        let cache =
            geodata_proto::GeoSiteList::decode(bytes.as_slice()).map_err(|x| {
                Error::InvalidConfig(format!("geosite decode failed: {}", x))
            })?;
        Ok(Self { cache })
    }

    #[cfg(test)]
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let bytes = tokio::fs::read(path).await?;
        let cache =
            geodata_proto::GeoSiteList::decode(bytes.as_slice()).map_err(|x| {
                Error::InvalidConfig(format!("geosite decode failed: {}", x))
            })?;
        Ok(Self { cache })
    }
}
