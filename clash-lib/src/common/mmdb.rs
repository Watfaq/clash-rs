use maxminddb::geoip2;
use std::{fs, net::IpAddr, path::Path, sync::Arc};
use tracing::{debug, info, warn};

use crate::{
    Error,
    common::{errors::map_io_error, utils::download},
};

use super::http::HttpClient;

pub struct Mmdb {
    reader: maxminddb::Reader<Vec<u8>>,
}

pub type MmdbLookup = Arc<dyn MmdbLookupTrait + Send + Sync>;

// mockall can't seem to mock the return value mmdb::Country<'a> with lifetime
// issue
#[derive(Debug)]
pub struct MmdbLookupCountry {
    pub country_code: String,
}

#[derive(Debug)]
pub struct MmdbLookupAsn {
    pub asn_name: String,
}

#[cfg_attr(test, mockall::automock)]
pub trait MmdbLookupTrait {
    fn lookup_country(&self, ip: IpAddr) -> std::io::Result<MmdbLookupCountry>;
    fn lookup_asn(&self, ip: IpAddr) -> std::io::Result<MmdbLookupAsn>;
}

impl MmdbLookupTrait for Mmdb {
    fn lookup_country(&self, ip: IpAddr) -> std::io::Result<MmdbLookupCountry> {
        self.reader
            .lookup::<geoip2::Country>(ip)
            .map_err(map_io_error)?
            .map(|c| MmdbLookupCountry {
                country_code: c
                    .country
                    .and_then(|x| x.iso_code)
                    .unwrap_or_default()
                    .to_string(),
            })
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "country not found",
            ))
    }

    fn lookup_asn(&self, ip: IpAddr) -> std::io::Result<MmdbLookupAsn> {
        self.reader
            .lookup::<geoip2::Asn>(ip)
            .map_err(map_io_error)?
            .map(|c| MmdbLookupAsn {
                asn_name: c
                    .autonomous_system_organization
                    .unwrap_or_default()
                    .to_string(),
            })
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "asn not found",
            ))
    }
}

impl Mmdb {
    pub async fn new<P: AsRef<Path>>(
        path: P,
        download_url: Option<String>,
        http_client: HttpClient,
    ) -> Result<Mmdb, Error> {
        debug!("mmdb path: {}", path.as_ref().to_string_lossy());
        let reader = Self::load_mmdb(path, download_url, &http_client).await?;
        Ok(Self { reader })
    }

    async fn load_mmdb<P: AsRef<Path>>(
        path: P,
        download_url: Option<String>,
        http_client: &HttpClient,
    ) -> Result<maxminddb::Reader<Vec<u8>>, Error> {
        let mmdb_file = path.as_ref().to_path_buf();

        if !mmdb_file.exists()
            || download_url
                .as_ref()
                .is_some_and(|x| x.contains("force=true"))
        {
            if let Some(url) = download_url.as_ref() {
                info!("downloading mmdb from {}", url);
                download(url, &mmdb_file, http_client).await.map_err(|x| {
                    Error::InvalidConfig(format!("mmdb download failed: {x}"))
                })?;
            } else {
                return Err(Error::InvalidConfig(format!(
                    "mmdb `{}` not found and mmdb_download_url is not set",
                    path.as_ref().to_string_lossy()
                )));
            }
        }

        match maxminddb::Reader::open_readfile(&path) {
            Ok(r) => Ok(r),
            Err(e) => match e {
                maxminddb::MaxMindDbError::InvalidDatabase(_)
                | maxminddb::MaxMindDbError::Io(_) => {
                    warn!(
                        "invalid mmdb `{}`: {}, trying to download again",
                        path.as_ref().to_string_lossy(),
                        e.to_string()
                    );

                    // try to download again
                    fs::remove_file(&mmdb_file)?;
                    if let Some(url) = download_url.as_ref() {
                        info!("downloading mmdb from {}", url);
                        download(url, &mmdb_file, http_client).await.map_err(
                            |x| {
                                Error::InvalidConfig(format!(
                                    "mmdb download failed: {x}"
                                ))
                            },
                        )?;
                        Ok(maxminddb::Reader::open_readfile(&path).map_err(|x| {
                            Error::InvalidConfig(format!(
                                "cant open mmdb `{}`: {}",
                                path.as_ref().to_string_lossy(),
                                x
                            ))
                        })?)
                    } else {
                        Err(Error::InvalidConfig(format!(
                            "mmdb `{}` not found and mmdb_download_url is not set",
                            path.as_ref().to_string_lossy()
                        )))
                    }
                }
                _ => Err(Error::InvalidConfig(format!(
                    "cant open mmdb `{}`: {}",
                    path.as_ref().to_string_lossy(),
                    e
                ))),
            },
        }
    }
}
