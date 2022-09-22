use crate::app::router::rules::RuleMatcher;
use crate::session::Session;
use log::warn;

pub struct RuleSet {
    pub rule_set: String,
    pub target: String,
}

impl RuleMatcher for RuleSet {
    fn apply(&self, sess: &Session) -> bool {
        warn!("RULE-SET not implemented yet");
        false
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }
}
