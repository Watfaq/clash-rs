use crate::app::router::rules::domain::Domain;
use crate::app::router::rules::domain_keyword::DomainKeyword;
use crate::app::router::rules::domain_suffix::DomainSuffix;
use crate::app::router::rules::ipcidr::IPCIDR;
use crate::app::router::rules::ruleset::RuleSet;
use crate::app::router::rules::RuleMatcher;
use crate::app::ThreadSafeDNSResolver;

use crate::config::internal::rule::Rule;
use crate::session::{Session, SocksAddr};

use crate::app::router::rules::final_::Final;
use std::sync::Arc;
use tokio::sync::RwLock;

mod mmdb;
mod rules;

pub struct Router {
    rules: Vec<Box<dyn RuleMatcher>>,
    dns_client: ThreadSafeDNSResolver,
}

pub type ThreadSafeRouter = Arc<RwLock<Router>>;

const MATCH: &str = "MATCH";

impl Router {
    pub fn new(rules: Vec<Rule>, dns_client: ThreadSafeDNSResolver, mmdb_path: String) -> Self {
        let mmdb = Arc::new(mmdb::MMDB::new(mmdb_path).expect("failed to load mmdb"));

        Self {
            rules: rules
                .into_iter()
                .map(|r| match r {
                    Rule::Domain { domain, target } => {
                        Box::new(Domain { domain, target }) as Box<dyn RuleMatcher>
                    }
                    Rule::DomainSuffix {
                        domain_suffix,
                        target,
                    } => Box::new(DomainSuffix {
                        suffix: domain_suffix,
                        target,
                    }),
                    Rule::DomainKeyword {
                        domain_keyword,
                        target,
                    } => Box::new(DomainKeyword {
                        keyword: domain_keyword,
                        target,
                    }),
                    Rule::IPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                    } => Box::new(IPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                        match_src: false,
                    }),
                    Rule::SRCIPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                    } => Box::new(IPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                        match_src: true,
                    }),

                    Rule::GeoIP {
                        target,
                        country_code,
                        no_resolve,
                    } => Box::new(rules::geoip::GeoIP {
                        target,
                        country_code,
                        no_resolve,
                        mmdb: mmdb.clone(),
                    }),
                    Rule::SRCPort { target, port } => Box::new(rules::port::Port {
                        port,
                        target,
                        is_src: true,
                    }),
                    Rule::DSTPort { target, port } => Box::new(rules::port::Port {
                        port,
                        target,
                        is_src: false,
                    }),
                    Rule::ProcessName => todo!(),
                    Rule::ProcessPath => todo!(),
                    Rule::RuleSet { rule_set, target } => Box::new(RuleSet { rule_set, target }),
                    Rule::Match { target } => Box::new(Final { target }),
                })
                .collect(),
            dns_client,
        }
    }

    pub async fn match_route<'a>(&'a self, sess: &'a Session) -> &str {
        let mut sess_resolved = false;
        let mut sess_dup = sess.clone();

        for r in self.rules.iter() {
            if sess.destination.is_domain() && r.should_resolve_ip() && !sess_resolved {
                if let Ok(ip) = self
                    .dns_client
                    .resolve(sess.destination.domain().unwrap())
                    .await
                {
                    if let Some(ip) = ip {
                        sess_dup.destination = SocksAddr::from((ip, sess.destination.port()));
                        sess_resolved = true;
                    }
                }
            }

            if r.apply(&sess_dup) {
                return r.target();
            }
        }

        MATCH
    }
}
