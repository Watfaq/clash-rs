use crate::app::router::rules::RuleMatcher;
use crate::session::Session;

#[derive(Clone)]
pub struct Port {
    pub port: u16,
    pub target: String,
    pub is_src: bool,
}

impl RuleMatcher for Port {
    fn apply(&self, sess: &Session) -> bool {
        if self.is_src {
            sess.source.port() == self.port
        } else {
            sess.destination.port() == self.port
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.port.to_string()
    }

    fn type_name(&self) -> &str {
        "Port"
    }
}
