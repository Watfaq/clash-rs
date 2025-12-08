use crate::{app::router::rules::RuleMatcher, session::{Network, Session}};

#[derive(Clone)]
pub struct NetworkRule {
    pub network: Network,
    pub target: String,
}

impl std::fmt::Display for NetworkRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} network {}", self.target, self.network)
    }
}

impl RuleMatcher for NetworkRule {
    fn apply(&self, sess: &Session) -> bool {
        sess.network == self.network
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.network.to_string()
    }

    fn type_name(&self) -> &str {
        "Network"
    }
}
