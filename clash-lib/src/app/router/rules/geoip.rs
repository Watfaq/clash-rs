use tracing::warn;

use super::RuleMatcher;
use crate::{common::mmdb::MmdbLookup, session::Session};

#[derive(Clone)]
pub struct GeoIP {
    pub target: String,
    pub country_code: String,
    pub no_resolve: bool,
    pub mmdb: Option<MmdbLookup>,
}

impl std::fmt::Display for GeoIP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GeoIP({} - {})", self.target, self.country_code)
    }
}

impl RuleMatcher for GeoIP {
    fn apply(&self, sess: &Session) -> bool {
        let ip = sess.resolved_ip.or(sess.destination.ip());

        if let Some(ip) = ip {
            if let Some(mmdb) = &self.mmdb {
                // Check if the IP matches the country code
                mmdb.lookup_country(ip)
                    .is_ok_and(|country| country.country_code == self.country_code)
            } else {
                warn!(
                    "GeoIP lookup failed: MMDB not available. Maybe config.mmdb is \
                     not set?"
                );
                false
            }
        } else {
            false
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.country_code.clone()
    }

    fn type_name(&self) -> &str {
        "GeoIP"
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }
}
