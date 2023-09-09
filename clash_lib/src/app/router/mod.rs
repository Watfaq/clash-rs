use crate::app::router::rules::domain::Domain;
use crate::app::router::rules::domain_keyword::DomainKeyword;
use crate::app::router::rules::domain_suffix::DomainSuffix;
use crate::app::router::rules::ipcidr::IPCIDR;
use crate::app::router::rules::ruleset::RuleSet;

use crate::common::http::new_http_client;
use crate::config::internal::rule::RuleType;
use crate::session::{Session, SocksAddr};

use crate::app::router::rules::final_::Final;
use std::sync::Arc;

use tracing::info;

use super::dns::ThreadSafeDNSResolver;

mod mmdb;
mod rules;
pub use rules::RuleMatcher;

pub struct Router {
    rules: Vec<Box<dyn RuleMatcher>>,
    dns_resolver: ThreadSafeDNSResolver,
}

pub type ThreadSafeRouter = Arc<Router>;

const MATCH: &str = "MATCH";

impl Router {
    pub async fn new(
        rules: Vec<RuleType>,
        dns_resolver: ThreadSafeDNSResolver,
        mmdb_path: String,
        mmdb_download_url: Option<String>,
    ) -> Self {
        let client = new_http_client(dns_resolver.clone()).expect("failed to create http client");
        let mmdb = Arc::new(
            mmdb::MMDB::new(mmdb_path, mmdb_download_url, client)
                .await
                .expect("failed to load mmdb"),
        );

        Self {
            rules: rules
                .into_iter()
                .map(|r| match r {
                    RuleType::Domain { domain, target } => {
                        Box::new(Domain { domain, target }) as Box<dyn RuleMatcher>
                    }
                    RuleType::DomainSuffix {
                        domain_suffix,
                        target,
                    } => Box::new(DomainSuffix {
                        suffix: domain_suffix,
                        target,
                    }),
                    RuleType::DomainKeyword {
                        domain_keyword,
                        target,
                    } => Box::new(DomainKeyword {
                        keyword: domain_keyword,
                        target,
                    }),
                    RuleType::IPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                    } => Box::new(IPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                        match_src: false,
                    }),
                    RuleType::SRCIPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                    } => Box::new(IPCIDR {
                        ipnet,
                        target,
                        no_resolve,
                        match_src: true,
                    }),

                    RuleType::GeoIP {
                        target,
                        country_code,
                        no_resolve,
                    } => Box::new(rules::geoip::GeoIP {
                        target,
                        country_code,
                        no_resolve,
                        mmdb: mmdb.clone(),
                    }),
                    RuleType::SRCPort { target, port } => Box::new(rules::port::Port {
                        port,
                        target,
                        is_src: true,
                    }),
                    RuleType::DSTPort { target, port } => Box::new(rules::port::Port {
                        port,
                        target,
                        is_src: false,
                    }),
                    RuleType::ProcessName => todo!(),
                    RuleType::ProcessPath => todo!(),
                    RuleType::RuleSet { rule_set, target } => {
                        Box::new(RuleSet { rule_set, target })
                    }
                    RuleType::Match { target } => Box::new(Final { target }),
                })
                .collect(),
            dns_resolver,
        }
    }

    pub async fn match_route<'a>(
        &'a self,
        sess: &'a Session,
    ) -> (&str, Option<&Box<dyn RuleMatcher>>) {
        let mut sess_resolved = false;
        let mut sess_dup = sess.clone();

        for r in self.rules.iter() {
            if sess.destination.is_domain() && r.should_resolve_ip() && !sess_resolved {
                if let Ok(ip) = self
                    .dns_resolver
                    .resolve(sess.destination.domain().unwrap(), false)
                    .await
                {
                    if let Some(ip) = ip {
                        sess_dup.destination = SocksAddr::from((ip, sess.destination.port()));
                        sess_resolved = true;
                    }
                }
            }

            if r.apply(&sess_dup) {
                info!("matched {} to target {}", &sess_dup, r.target());
                return (r.target(), Some(r));
            }
        }

        (MATCH, None)
    }

    /// API handlers
    pub fn get_all_rules(&self) -> &Vec<Box<dyn RuleMatcher>> {
        &self.rules
    }
}
