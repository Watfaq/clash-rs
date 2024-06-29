use crate::{
    app::router::rules::RuleMatcher,
    session::{Session, SocksAddr},
};

#[derive(Clone)]
pub struct IpCidr {
    pub ipnet: ipnet::IpNet,
    pub target: String,
    pub match_src: bool,
    pub no_resolve: bool,
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.target,
            if self.match_src { "src" } else { "dst" },
            self.ipnet
        )
    }
}

impl RuleMatcher for IpCidr {
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

    fn payload(&self) -> String {
        self.ipnet.to_string()
    }

    fn type_name(&self) -> &str {
        "IPCIDR"
    }
}
