use crate::{
    app::{
        remote_content_manager::providers::rule_provider::ThreadSafeRuleProvider,
        router::rules::RuleMatcher,
    },
    session::Session,
};

#[derive(Clone)]
pub struct RuleSet {
    pub rule_set: String,
    pub target: String,
    pub rule_provider: ThreadSafeRuleProvider,
}

impl RuleSet {
    pub fn new(
        rule_set: String,
        target: String,
        rule_provider: ThreadSafeRuleProvider,
    ) -> Self {
        Self {
            rule_set,
            target,
            rule_provider,
        }
    }
}

impl std::fmt::Display for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} rule-set {}", self.target, self.rule_set)
    }
}

impl RuleMatcher for RuleSet {
    fn apply(&self, sess: &Session) -> bool {
        self.rule_provider.search(sess)
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.rule_set.clone()
    }

    fn type_name(&self) -> &str {
        "RuleSet"
    }
}
