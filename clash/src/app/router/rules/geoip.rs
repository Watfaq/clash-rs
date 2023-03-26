use std::sync::Arc;

use crate::{app::router::mmdb, session::Session};

use super::RuleMatcher;

pub struct GeoIP {
    pub target: String,
    pub country_code: String,
    pub no_resolve: bool,
    pub mmdb: Arc<mmdb::MMDB>,
}

impl RuleMatcher for GeoIP {
    fn apply(&self, sess: &Session) -> bool {
        match sess.destination {
            crate::session::SocksAddr::Ip(addr) => match self.mmdb.lookup(addr.ip()) {
                Ok(country) => {
                    country
                        .country
                        .map(|x| x.iso_code)
                        .unwrap_or_default()
                        .unwrap_or_default()
                        == self.country_code
                }
                Err(_) => todo!(),
            },
            crate::session::SocksAddr::Domain(_, _) => false,
        }
    }
    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }
}
