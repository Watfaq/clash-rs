use crate::app::router::rules::RuleMatcher;
use crate::session::{Session, SocksAddr};


pub struct IPCIDR {
    pub ipnet: ipnet::IpNet,
    pub target: String,
    pub match_src: bool,
    pub no_resolve: bool,
}

impl RuleMatcher for IPCIDR {
    fn apply(&self, sess: &Session) -> bool {
        match self.match_src {
            true => self.ipnet.contains(&sess.source.ip()),
            false => match &sess.destination {
                SocksAddr::Ip(ip) => self.ipnet.contains(&ip.ip()),
                SocksAddr::Domain(_, _) => false,
            },
        }
    }
    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }
}
