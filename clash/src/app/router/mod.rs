use crate::app::router::rules::domain::Domain;
use crate::app::router::rules::domain_keyword::DomainKeyword;
use crate::app::router::rules::domain_suffix::DomainSuffix;
use crate::app::router::rules::ipcidr::IPCIDR;
use crate::app::router::rules::RuleMatcher;
use crate::app::ThreadSafeAsyncDnsClient;
use crate::config::internal::rule::Rule;
use crate::session::{Session, SocksAddr};
use std::borrow::BorrowMut;
use std::sync::Arc;
use tokio::sync::RwLock;

mod rules;

pub struct Router {
    rules: Vec<Box<dyn RuleMatcher>>,
    dns_client: ThreadSafeAsyncDnsClient,
}

pub type ThreadSafeRouter = Arc<RwLock<Router>>;

const MATCH: &str = "MATCH";

impl Router {
    pub fn new(rules: Vec<Rule>, dns_client: ThreadSafeAsyncDnsClient) -> Self {
        Self {
            rules: rules
                .into_iter()
                .map(|r| match r {
                    Rule::Domain { domain, target } => Domain { domain, target },
                    Rule::DomainSuffix {
                        domain_suffix,
                        target,
                    } => DomainSuffix {
                        suffix: domain_suffix,
                        target,
                    },
                    Rule::DomainKeyword {
                        domain_keyword,
                        target,
                    } => DomainKeyword {
                        keyword: domain_keyword,
                        target,
                    },
                    Rule::IPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                    } => IPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                        match_src: false,
                    },
                    Rule::SRCIPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                    } => IPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                        match_src: true,
                    },

                    Rule::GeoIP() => {}
                    Rule::SRCPort => {}
                    Rule::DSTPort => {}
                    Rule::ProcessName => {}
                    Rule::ProcessPath => {}
                    Rule::Match { .. } => todo!(),
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
                let ip = self
                    .dns_client
                    .read()?
                    .resolve(sess.destination.domain().unwrap().as_str())
                    .await?;
                sess_dup.destination = SocksAddr::from((ip, sess.destination.port()));
                sess_resolved = true;
            }

            if r.apply(&sess_dup) {
                r.target()
            }
        }

        MATCH
    }
}
