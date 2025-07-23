use super::{
    dns::ThreadSafeDNSResolver,
    remote_content_manager::providers::{
        file_vehicle, http_vehicle,
        rule_provider::{RuleProviderImpl, ThreadSafeRuleProvider},
    },
};
use crate::{
    Error,
    app::router::rules::{
        domain::Domain, domain_keyword::DomainKeyword, domain_suffix::DomainSuffix,
        final_::Final, ipcidr::IpCidr, ruleset::RuleSet,
    },
    config::internal::{config::RuleProviderDef, rule::RuleType},
    print_and_exit,
    session::Session,
};

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use hyper::Uri;
use rules::domain_regex::DomainRegex;
use tracing::{error, info, trace};

mod rules;

use crate::common::{geodata::GeoDataLookup, mmdb::MmdbLookup};
pub use rules::RuleMatcher;

pub struct Router {
    rules: Vec<Box<dyn RuleMatcher>>,
    dns_resolver: ThreadSafeDNSResolver,

    asn_mmdb: Option<MmdbLookup>,
}

pub type ThreadSafeRouter = Arc<Router>;

const MATCH: &str = "MATCH";

impl Router {
    pub async fn new(
        rules: Vec<RuleType>,
        rule_providers: HashMap<String, RuleProviderDef>,
        dns_resolver: ThreadSafeDNSResolver,
        country_mmdb: Option<MmdbLookup>,
        asn_mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Self {
        let mut rule_provider_registry = HashMap::new();

        Self::load_rule_providers(
            rule_providers,
            &mut rule_provider_registry,
            dns_resolver.clone(),
            country_mmdb.clone(),
            geodata.clone(),
            cwd,
        )
        .await
        .ok();

        Self {
            rules: rules
                .into_iter()
                .map(|r| {
                    map_rule_type(
                        r,
                        country_mmdb.clone(),
                        geodata.clone(),
                        Some(&rule_provider_registry),
                    )
                })
                .collect(),
            dns_resolver,

            asn_mmdb,
        }
    }

    /// this mutates the session, attaching resolved IP and ASN
    pub async fn match_route(
        &self,
        sess: &mut Session,
    ) -> (&str, Option<&Box<dyn RuleMatcher>>) {
        let mut sess_resolved = false;

        for r in self.rules.iter() {
            if sess.destination.is_domain()
                && r.should_resolve_ip()
                && !sess_resolved
                && let Ok(Some(ip)) = self
                    .dns_resolver
                    .resolve(sess.destination.domain().unwrap(), false)
                    .await
            {
                sess.resolved_ip = Some(ip);
                sess_resolved = true;
            }

            let maybe_ip = sess.resolved_ip.or(sess.destination.ip());
            if let (Some(ip), Some(asn_mmdb)) = (maybe_ip, &self.asn_mmdb) {
                // try simplified mmdb first
                let rv = asn_mmdb.lookup_country(ip);
                if let Ok(country) = rv {
                    sess.asn = Some(country.country_code);
                }
                if sess.asn.is_none() {
                    match asn_mmdb.lookup_asn(ip) {
                        Ok(asn) => {
                            trace!("asn for {} is {:?}", ip, asn);
                            sess.asn = Some(asn.asn_name);
                        }
                        Err(e) => {
                            trace!("failed to lookup ASN for {}: {}", ip, e);
                        }
                    }
                }
            }

            if r.apply(sess) {
                info!(
                    "matched {} to target {}[{}]",
                    &sess,
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
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Result<(), Error> {
        for (name, provider) in rule_providers.into_iter() {
            match provider {
                RuleProviderDef::Http(http) => {
                    let vehicle = http_vehicle::Vehicle::new(
                        http.url.parse::<Uri>().unwrap_or_else(|_| {
                            print_and_exit!("invalid provider url: {}", http.url)
                        }),
                        http.path,
                        Some(cwd.clone()),
                        resolver.clone(),
                    );

                    // Default to yaml if not specified
                    let format = http.format.unwrap_or_default();
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        http.behavior,
                        format,
                        Some(Duration::from_secs(http.interval)),
                        Some(Arc::new(vehicle)),
                        mmdb.clone(),
                        geodata.clone(),
                        http.inline_rules,
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::File(file) => {
                    let vehicle = file_vehicle::Vehicle::new(
                        PathBuf::from(cwd.clone())
                            .join(&file.path)
                            .to_str()
                            .unwrap(),
                    );

                    // Default to yaml if not specified
                    let format = file.format.unwrap_or_default();
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        file.behavior,
                        format,
                        Some(Duration::from_secs(file.interval.unwrap_or_default())),
                        Some(Arc::new(vehicle)),
                        mmdb.clone(),
                        geodata.clone(),
                        file.inline_rules,
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::Inline(inline) => {
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        inline.behavior,
                        Default::default(), /* format really doesn't matter for
                                             * inline rules */
                        None,
                        None,
                        mmdb.clone(),
                        geodata.clone(),
                        Some(inline.inline_rules),
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
            }
        }

        for p in rule_provider_registry.values() {
            let p = p.clone();
            tokio::spawn(async move {
                info!("initializing rule provider {}", p.name());
                match p.initialize().await {
                    Ok(_) => {
                        info!("rule provider {} initialized", p.name());
                    }
                    Err(err) => {
                        error!(
                            "failed to initialize rule provider {}: {}",
                            p.name(),
                            err
                        );
                    }
                }
            });
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
    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
    rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
) -> Box<dyn RuleMatcher> {
    match rule_type {
        RuleType::Domain { domain, target } => {
            Box::new(Domain { domain, target }) as Box<dyn RuleMatcher>
        }
        RuleType::DomainRegex { regex, target } => {
            Box::new(DomainRegex { regex, target })
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
        RuleType::IpCidr {
            ipnet,
            target,
            no_resolve,
        } => Box::new(IpCidr {
            ipnet,
            target,
            no_resolve,
            match_src: false,
        }),
        RuleType::SrcCidr {
            ipnet,
            target,
            no_resolve,
        } => Box::new(IpCidr {
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
        RuleType::GeoSite {
            target,
            country_code,
        } => {
            let res = rules::geodata::GeoSiteMatcher::new(
                country_code,
                target,
                geodata.as_ref(),
            )
            .unwrap();
            Box::new(res) as _
        }
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
                    .unwrap_or_else(|| {
                        print_and_exit!("rule provider {} not found", rule_set)
                    })
                    .clone(),
            )),
            None => {
                // this is called in remote rule provider with no rule provider
                // registry, in this case, we should panic
                unreachable!("you shouldn't nest rule-set within another rule-set")
            }
        },
        RuleType::Match { target } => Box::new(Final { target }),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::Ok;

    use crate::{
        app::dns::{MockClashResolver, SystemResolver},
        common::{
            geodata::{DEFAULT_GEOSITE_DOWNLOAD_URL, GeoData},
            http::new_http_client,
            mmdb::{DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL, Mmdb},
        },
        config::internal::rule::RuleType,
        session::Session,
        tests::initialize,
    };

    #[tokio::test]
    async fn test_route_match() {
        initialize();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|host, _| {
            if host == "china.com" {
                Ok(Some("114.114.114.114".parse().unwrap()))
            } else if host == "t.me" {
                Ok(Some("149.154.0.1".parse().unwrap()))
            } else if host == "git.io" {
                Ok(Some("8.8.8.8".parse().unwrap()))
            } else {
                Ok(None)
            }
        });
        let mock_resolver = Arc::new(mock_resolver);

        let real_resolver = Arc::new(SystemResolver::new(false).unwrap());

        let client = new_http_client(real_resolver.clone()).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();

        let mmdb = Mmdb::new(
            temp_dir.path().join("mmdb.mmdb"),
            DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL.to_string(),
            client,
        )
        .await
        .unwrap();

        let client = new_http_client(real_resolver.clone()).unwrap();

        let geodata = GeoData::new(
            temp_dir.path().join("geodata.geodata"),
            DEFAULT_GEOSITE_DOWNLOAD_URL.to_string(),
            client,
        )
        .await
        .unwrap();

        let router = super::Router::new(
            vec![
                RuleType::GeoIP {
                    target: "DIRECT".to_string(),
                    country_code: "CN".to_string(),
                    no_resolve: false,
                },
                RuleType::DomainRegex {
                    regex: regex::Regex::new(r"^regex").unwrap(),
                    target: "regex-match".to_string(),
                },
                RuleType::DomainSuffix {
                    domain_suffix: "t.me".to_string(),
                    target: "DS".to_string(),
                },
                RuleType::IpCidr {
                    ipnet: "149.154.0.0/16".parse().unwrap(),
                    target: "IC".to_string(),
                    no_resolve: false,
                },
                RuleType::DomainSuffix {
                    domain_suffix: "git.io".to_string(),
                    target: "DS2".to_string(),
                },
            ],
            Default::default(),
            mock_resolver,
            Some(Arc::new(mmdb)),
            None,
            Some(Arc::new(geodata)),
            temp_dir.path().to_str().unwrap().to_string(),
        )
        .await;

        let cases = vec![
            ("china.com", "DIRECT", "should resolve and match IP"),
            ("regex", "regex-match", "should match regex"),
            ("t.me", "DS", "should match domain"),
            (
                "git.io",
                "DS2",
                "should still match domain after previous rule resolved IP and non \
                 match",
            ),
            (
                "no-match",
                "MATCH",
                "should fallback to MATCH when nothing matched",
            ),
            ("149.154.0.1", "IC", "should match CIDR"),
        ];

        for (domain, target, desc) in cases {
            assert_eq!(
                router
                    .match_route(&mut Session {
                        destination: crate::session::SocksAddr::Domain(
                            domain.to_string(),
                            1111
                        ),
                        ..Default::default()
                    })
                    .await
                    .0,
                target,
                "{}",
                desc
            );
        }
    }
}
