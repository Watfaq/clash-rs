use super::RuleMatcher;

pub struct Process {
    pub name: String,
    pub target: String,
    #[allow(dead_code)]
    pub name_only: bool,
}

impl RuleMatcher for Process {
    fn apply(&self, _sess: &crate::session::Session) -> bool {
        // TODO: implement this
        false
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.name.clone()
    }

    fn type_name(&self) -> &str {
        "Process"
    }
}
