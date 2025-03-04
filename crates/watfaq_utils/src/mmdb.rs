use std::{net::IpAddr, path::Path};

use maxminddb::{MaxMindDBError, geoip2};

pub struct Mmdb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl Mmdb {
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Mmdb, MaxMindDBError> {
        let reader = maxminddb::Reader::open_readfile(&path)?;
        Ok(Self { reader })
    }

    pub fn lookup_country(
        &self,
        ip: IpAddr,
    ) -> Result<geoip2::Country, MaxMindDBError> {
        self.reader.lookup::<geoip2::Country>(ip)
    }

    pub fn lookup_asn(&self, ip: IpAddr) -> Result<geoip2::Asn, MaxMindDBError> {
        self.reader.lookup::<geoip2::Asn>(ip)
    }
}
