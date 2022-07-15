use crate::session;

use super::RuleMatcher;

pub struct Domain {
    pub domain: String,
    pub target: String,
}

impl RuleMatcher for Domain {
    fn apply(&self, sess: &session::Session) -> bool {
        match &sess.destination {
            session::SocksAddr::Ip(_) => false,
            session::SocksAddr::Domain(domain, _) => self.domain == domain,
        }
    }

    fn target(&self) -> &str {
        &self.target
    }
}
