use crate::session;

use super::RuleMatcher;

#[derive(Clone)]
pub struct Domain {
    pub domain: String,
    pub target: String,
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} domain {}", self.target, self.domain)
    }
}

impl RuleMatcher for Domain {
    fn apply(&self, sess: &session::Session) -> bool {
        match &sess.destination {
            session::TargetAddr::Socket(_) => false,
            session::TargetAddr::Domain(domain, _) => &self.domain == domain,
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.domain.clone()
    }

    fn type_name(&self) -> &str {
        "Domain"
    }
}
