use crate::app::router::rules::RuleMatcher;
use crate::session::Session;

pub struct Final {
    pub target: String,
}

impl RuleMatcher for Final {
    fn apply(&self, _sess: &Session) -> bool {
        true
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }
}
