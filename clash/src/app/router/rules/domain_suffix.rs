use crate::app::router::rules::RuleMatcher;
use crate::session::{Session, SocksAddr};

pub struct DomainSuffix {
    pub suffix: String,
    pub target: String,
}

impl RuleMatcher for DomainSuffix {
    fn apply(&self, sess: &Session) -> bool {
        match &sess.destination {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(domain, _) => {
                domain.ends_with("."+&self.suffix) || domain == self.suffix
            }
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }
}