use std::{fs, net::IpAddr, path::Path};

use maxminddb::geoip2;
use tracing::{debug, info, warn};

use crate::{
    common::{errors::map_io_error, utils::download},
    Error,
};

use super::http::HttpClient;

pub struct Mmdb {
    reader: maxminddb::Reader<Vec<u8>>,
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

        if !mmdb_file.exists() {
            if let Some(url) = download_url.as_ref() {
                info!("downloading mmdb from {}", url);
                download(url, &mmdb_file, http_client).await.map_err(|x| {
                    Error::InvalidConfig(format!("mmdb download failed: {}", x))
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
                maxminddb::MaxMindDBError::InvalidDatabaseError(_)
                | maxminddb::MaxMindDBError::IoError(_) => {
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
                                    "mmdb download failed: {}",
                                    x
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

    pub fn lookup_contry(&self, ip: IpAddr) -> std::io::Result<geoip2::Country> {
        self.reader
            .lookup::<geoip2::Country>(ip)
            .map_err(map_io_error)
    }

    pub fn lookup_asn(&self, ip: IpAddr) -> std::io::Result<geoip2::Asn> {
        self.reader.lookup::<geoip2::Asn>(ip).map_err(map_io_error)
    }
}
