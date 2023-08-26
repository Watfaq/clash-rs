use crate::session;

use super::RuleMatcher;

pub struct DomainKeyword {
    pub keyword: String,
    pub target: String,
}

impl RuleMatcher for DomainKeyword {
    fn apply(&self, sess: &session::Session) -> bool {
        match &sess.destination {
            session::SocksAddr::Ip(_) => false,
            session::SocksAddr::Domain(domain, _) => domain.contains(&self.keyword),
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> Box<dyn erased_serde::Serialize + Send> {
        Box::new(self.keyword.clone())
    }

    fn type_name(&self) -> &str {
        "DomainKeyword"
    }
}
