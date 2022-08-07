use crate::session::Session;


pub mod domain;
pub mod domain_keyword;
pub mod domain_suffix;
pub mod final_;
pub mod geoip;
pub mod ipcidr;
pub mod port;
pub mod process;

pub trait RuleMatcher: Send + Sync + Unpin {
    fn apply(&self, sess: &Session) -> bool;
    fn target(&self) -> &str;

    fn should_resolve_ip(&self) -> bool {
        false
    }
}
