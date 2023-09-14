use crate::app::router::rules::domain::Domain;
use crate::app::router::rules::domain_keyword::DomainKeyword;
use crate::app::router::rules::domain_suffix::DomainSuffix;
use crate::app::router::rules::ipcidr::IPCIDR;
use crate::app::router::rules::ruleset::RuleSet;
use crate::Error;

use crate::common::http::new_http_client;
use crate::config::internal::config::RuleProviderDef;
use crate::config::internal::rule::RuleType;
use crate::session::{Session, SocksAddr};

use crate::app::router::rules::final_::Final;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use http::Uri;
use tracing::{error, info, warn};

pub use self::mmdb::MMDB;

use super::dns::ThreadSafeDNSResolver;
use super::remote_content_manager::providers::rule_provider::{
    RuleProviderImpl, ThreadSafeRuleProvider,
};
use super::remote_content_manager::providers::{file_vehicle, http_vehicle};

mod mmdb;
mod rules;
pub use rules::RuleMatcher;

pub struct Router {
    rules: Vec<Box<dyn RuleMatcher>>,
    rule_provider_registry: HashMap<String, ThreadSafeRuleProvider>,
    dns_resolver: ThreadSafeDNSResolver,
}

pub type ThreadSafeRouter = Arc<Router>;

const MATCH: &str = "MATCH";

impl Router {
    pub async fn new(
        rules: Vec<RuleType>,
        rule_providers: HashMap<String, RuleProviderDef>,
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

        let mut rule_provider_registry = HashMap::new();

        Self::load_rule_providers(
            rule_providers,
            &mut rule_provider_registry,
            dns_resolver.clone(),
            mmdb.clone(),
        )
        .await
        .ok();

        Self {
            rules: rules
                .into_iter()
                .map(|r| map_rule_type(r, mmdb.clone(), Some(&rule_provider_registry)))
                .collect(),
            dns_resolver,
            rule_provider_registry,
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
                info!(
                    "matched {} to target {}[{}]",
                    &sess_dup,
                    r.target(),
                    r.type_name()
                );
                return (r.target(), Some(r));
            }
        }

        (MATCH, None)
    }

    async fn load_rule_providers(
        rule_providers: HashMap<String, RuleProviderDef>,
        rule_provider_registry: &mut HashMap<String, ThreadSafeRuleProvider>,
        resolver: ThreadSafeDNSResolver,
        mmdb: Arc<MMDB>,
    ) -> Result<(), Error> {
        for (name, provider) in rule_providers.into_iter() {
            match provider {
                RuleProviderDef::Http(http) => {
                    let vehicle = http_vehicle::Vehicle::new(
                        http.url
                            .parse::<Uri>()
                            .expect(format!("invalid provider url: {}", http.url).as_str()),
                        http.path,
                        resolver.clone(),
                    );

                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        http.behavior,
                        Duration::from_secs(http.interval),
                        Arc::new(vehicle),
                        mmdb.clone(),
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::File(file) => {
                    let vehicle = file_vehicle::Vehicle::new(&file.path);

                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        file.behavior,
                        Duration::from_secs(file.interval.unwrap_or_default()),
                        Arc::new(vehicle),
                        mmdb.clone(),
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
            }
        }

        for p in rule_provider_registry.values() {
            info!("initializing rule provider {}", p.name());
            match p.initialize().await {
                Ok(_) => {
                    info!("rule provider {} initialized", p.name());
                }
                Err(err) => {
                    error!("failed to initialize rule provider {}: {}", p.name(), err);
                }
            }
        }

        Ok(())
    }

    /// API handlers
    pub fn get_all_rules(&self) -> &Vec<Box<dyn RuleMatcher>> {
        &self.rules
    }
}

pub fn map_rule_type(
    rule_type: RuleType,
    mmdb: Arc<MMDB>,
    rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
) -> Box<dyn RuleMatcher> {
    match rule_type {
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
        RuleType::ProcessName {
            process_name,
            target,
        } => Box::new(rules::process::Process {
            name: process_name,
            target,
            name_only: true,
        }),
        RuleType::ProcessPath {
            process_path,
            target,
        } => Box::new(rules::process::Process {
            name: process_path,
            target,
            name_only: false,
        }),
        RuleType::RuleSet { rule_set, target } => match rule_provider_registry {
            Some(rule_provider_registry) => Box::new(RuleSet::new(
                rule_set.clone(),
                target,
                rule_provider_registry
                    .get(&rule_set)
                    .expect(format!("rule provider {} not found", rule_set).as_str())
                    .clone(),
            )),
            None => unreachable!("you shouldn't next rule-set within another rule-set"),
        },
        RuleType::Match { target } => Box::new(Final { target }),
    }
}
