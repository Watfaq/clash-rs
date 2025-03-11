use std::fmt::Display;

use crate::session;

use super::RuleMatcher;

#[derive(Clone)]
pub struct DomainKeyword {
    pub keyword: String,
    pub target: String,
}

impl Display for DomainKeyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} keyword {}", self.target, self.keyword)
    }
}

impl RuleMatcher for DomainKeyword {
    fn apply(&self, sess: &session::Session) -> bool {
        match &sess.destination {
            session::TargetAddr::Socket(_) => false,
            session::TargetAddr::Domain(domain, _) => domain.contains(&self.keyword),
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.keyword.to_owned()
    }

    fn type_name(&self) -> &str {
        "DomainKeyword"
    }
}
