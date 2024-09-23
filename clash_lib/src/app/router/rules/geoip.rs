use std::sync::Arc;

use tracing::debug;

use crate::{common::mmdb, session::Session};

use super::RuleMatcher;

#[derive(Clone)]
pub struct GeoIP {
    pub target: String,
    pub country_code: String,
    pub no_resolve: bool,
    pub mmdb: Arc<mmdb::Mmdb>,
}

impl std::fmt::Display for GeoIP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GeoIP({} - {})", self.target, self.country_code)
    }
}

impl RuleMatcher for GeoIP {
    fn apply(&self, sess: &Session) -> bool {
        let ip = if self.no_resolve {
            sess.destination.ip()
        } else {
            sess.resolved_ip
        };

        if let Some(ip) = ip {
            match self.mmdb.lookup(ip) {
                Ok(country) => {
                    country
                        .country
                        .map(|x| x.iso_code)
                        .unwrap_or_default()
                        .unwrap_or_default()
                        == self.country_code
                }
                Err(e) => {
                    debug!("GeoIP lookup failed: {}", e);
                    false
                }
            }
        } else {
            false
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }

    fn payload(&self) -> String {
        self.country_code.clone()
    }

    fn type_name(&self) -> &str {
        "GeoIP"
    }
}
