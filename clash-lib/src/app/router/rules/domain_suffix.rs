use crate::{
    app::router::rules::RuleMatcher,
    session::{Session, SocksAddr},
};

#[derive(Clone)]
pub struct DomainSuffix {
    pub suffix: String,
    pub target: String,
}

impl std::fmt::Display for DomainSuffix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} suffix {}", self.target, self.suffix)
    }
}

impl RuleMatcher for DomainSuffix {
    fn apply(&self, sess: &Session) -> bool {
        match &sess.destination {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(domain, _) => {
                domain.ends_with((String::from(".") + self.suffix.as_str()).as_str())
                    || domain == &self.suffix
            }
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.suffix.clone()
    }

    fn type_name(&self) -> &str {
        "DomainSuffix"
    }
}
