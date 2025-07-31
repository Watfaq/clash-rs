use super::http::HttpClient;
use crate::{Error, common::utils::download};
use prost::Message;
use std::path::Path;
use tracing::{debug, info};

pub static DEFAULT_GEOSITE_DOWNLOAD_URL: &str = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202406182210/geosite.dat";

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
        download_url: String,
        http_client: HttpClient,
    ) -> Result<Self, Error> {
        debug!("geosite path: {}", path.as_ref().to_string_lossy());

        let geosite_file = path.as_ref().to_path_buf();

        if !geosite_file.exists() || download_url.contains("force=true") {
            info!("downloading geodata from {}", download_url);
            download(&download_url, &geosite_file, &http_client)
                .await
                .map_err(|x| {
                    Error::InvalidConfig(format!("geosite download failed: {x}"))
                })?;
        }
        let bytes = tokio::fs::read(path).await?;
        let cache =
            geodata_proto::GeoSiteList::decode(bytes.as_slice()).map_err(|x| {
                Error::InvalidConfig(format!("geosite decode failed: {x}"))
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
