use std::{net::IpAddr, path::Path};

use maxminddb::geoip2;

use crate::{common::errors::map_io_error, Error};

pub struct MMDB {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl MMDB {
    pub fn new<P: AsRef<Path>>(path: P) -> anyhow::Result<MMDB> {
        let cwd = std::env::current_dir().unwrap();
        let reader = maxminddb::Reader::open_readfile(&path).map_err(|x| {
            Error::InvalidConfig(format!(
                "cant open mmdb `{}/{}`: {}",
                cwd.to_string_lossy(),
                path.as_ref().to_string_lossy(),
                x.to_string()
            ))
        })?;
        Ok(MMDB { reader })
    }

    pub fn lookup(&self, ip: IpAddr) -> anyhow::Result<geoip2::Country> {
        self.reader
            .lookup(ip)
            .map_err(map_io_error)
            .map_err(|x| x.into())
    }
}
