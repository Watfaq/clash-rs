use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone)]
/// A final rule that matches all sessions
pub struct Final {
    pub target: String,
}

impl std::fmt::Display for Final {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} final", self.target)
    }
}

impl RuleMatcher for Final {
    fn apply(&self, _sess: &Session) -> bool {
        true
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        "".to_owned()
    }

    fn type_name(&self) -> &str {
        "Match"
    }
}
