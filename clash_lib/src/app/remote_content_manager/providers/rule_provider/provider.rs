use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::{
    Error,
    app::{
        remote_content_manager::providers::{
            Provider, ProviderType, ProviderVehicleType, ThreadSafeProviderVehicle,
            fetcher::Fetcher,
        },
        router::{RuleMatcher, map_rule_type},
    },
    common::{
        errors::map_io_error, geodata::GeoData, mmdb::Mmdb, succinct_set, trie,
    },
    config::internal::rule::RuleType,
    session::Session,
};

use super::cidr_trie::CidrTrie;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    pub payload: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetFormat {
    #[default]
    Yaml,
    Text,
    Mrs,
}

impl Display for RuleSetFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSetFormat::Yaml => write!(f, "yaml"),
            RuleSetFormat::Text => write!(f, "text"),
            RuleSetFormat::Mrs => write!(f, "mrs"),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetBehavior {
    Domain,
    Ipcidr,
    Classical,
}

impl Display for RuleSetBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSetBehavior::Domain => write!(f, "Domain"),
            RuleSetBehavior::Ipcidr => write!(f, "IPCIDR"),
            RuleSetBehavior::Classical => write!(f, "Classical"),
        }
    }
}

pub enum RuleContent {
    // the left will converted into a right
    Domain(succinct_set::DomainSet),
    Ipcidr(Box<CidrTrie>),
    Classical(Vec<Box<dyn RuleMatcher>>),
}

struct Inner {
    content: RuleContent,
}

pub trait RuleProvider: Provider {
    fn search(&self, sess: &Session) -> bool;
    fn behavior(&self) -> RuleSetBehavior;
    fn format(&self) -> RuleSetFormat;
}

pub type ThreadSafeRuleProvider = Arc<dyn RuleProvider + Send + Sync>;

type RuleUpdater =
    Box<dyn Fn(RuleContent) -> BoxFuture<'static, ()> + Send + Sync + 'static>;
type RuleParser =
    Box<dyn Fn(&[u8]) -> anyhow::Result<RuleContent> + Send + Sync + 'static>;

pub struct RuleProviderImpl {
    fetcher: Fetcher<RuleUpdater, RuleParser>,
    inner: std::sync::Arc<tokio::sync::RwLock<Inner>>,
    behavior: RuleSetBehavior,
    format: RuleSetFormat,
}

impl RuleProviderImpl {
    pub fn new(
        name: String,
        behavior: RuleSetBehavior,
        format: RuleSetFormat,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        mmdb: Arc<Mmdb>,
        geodata: Arc<GeoData>,
    ) -> Self {
        let inner = Arc::new(tokio::sync::RwLock::new(Inner {
            content: match behavior {
                RuleSetBehavior::Domain => {
                    RuleContent::Domain(succinct_set::DomainSet::default())
                }
                RuleSetBehavior::Ipcidr => {
                    RuleContent::Ipcidr(Box::new(CidrTrie::new()))
                }
                RuleSetBehavior::Classical => RuleContent::Classical(vec![]),
            },
        }));

        let inner_clone = inner.clone();

        let n = name.clone();
        let updater: RuleUpdater =
            Box::new(move |input: RuleContent| -> BoxFuture<'static, ()> {
                let n = n.clone(); // Clone name for the async block
                let inner: Arc<tokio::sync::RwLock<Inner>> = inner_clone.clone();
                Box::pin(async move {
                    let mut inner = inner.write().await;
                    trace!("updated rules for provider: {}", n);
                    inner.content = input;
                })
            });

        let n_parser = name.clone(); // Clone name specifically for the parser closure
        let current_behavior = behavior;
        let current_format = format;
        let parser: RuleParser =
            Box::new(move |input: &[u8]| -> anyhow::Result<RuleContent> {
                match current_format {
                    RuleSetFormat::Yaml => {
                        let scheme: ProviderScheme = serde_yaml::from_slice(input)
                            .map_err(|x| {
                            Error::InvalidConfig(format!(
                                "rule provider parse error (yaml) {}: {}",
                                n_parser, x
                            ))
                        })?;
                        // For Yaml, we still need to convert Vec<String> to
                        // RuleContent
                        make_rules(
                            current_behavior,
                            scheme.payload,
                            mmdb.clone(),
                            geodata.clone(),
                        )
                        .map_err(anyhow::Error::new)
                    }
                    RuleSetFormat::Text => {
                        let text = std::str::from_utf8(input).map_err(|e| {
                            Error::InvalidConfig(format!(
                                "invalid utf-8 in text rule provider {}: {}",
                                n_parser, e
                            ))
                        })?;

                        let payload: Vec<String> = text
                            .lines()
                            .map(str::trim)
                            .filter(|line| {
                                !line.is_empty()
                                    && !line.starts_with('#')
                                    && !line.starts_with("//")
                            })
                            .map(String::from)
                            .collect();
                        // For Text, we also convert Vec<String> to RuleContent
                        make_rules(
                            current_behavior,
                            payload,
                            mmdb.clone(),
                            geodata.clone(),
                        )
                        .map_err(anyhow::Error::new)
                    }
                    RuleSetFormat::Mrs => {
                        if matches!(current_behavior, RuleSetBehavior::Classical) {
                            return Err(anyhow::Error::new(Error::InvalidConfig(
                                format!(
                                    "MRS format is not supported for classical \
                                     behavior in rule provider {}",
                                    n_parser
                                ),
                            )));
                        }
                        // Parse MRS format using the updated function signature.
                        // It directly returns the required RuleContent.
                        super::mrs::rules_mrs_parse(input, current_behavior)
                    }
                }
            });

        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater));

        Self {
            fetcher,
            inner,
            behavior,
            format,
        }
    }
}

#[async_trait]
impl RuleProvider for RuleProviderImpl {
    fn search(&self, sess: &Session) -> bool {
        let inner = self.inner.try_read();

        match inner {
            Ok(inner) => match &inner.content {
                RuleContent::Domain(set) => set.has(&sess.destination.host()),
                RuleContent::Ipcidr(trie) => trie.contains(
                    sess.destination
                        .ip()
                        .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                ),
                RuleContent::Classical(rules) => {
                    for rule in rules.iter() {
                        if rule.apply(sess) {
                            return true;
                        }
                    }
                    false
                }
            },
            Err(_) => {
                debug!("rule provider {} is busy", self.name());
                false
            }
        }
    }

    fn behavior(&self) -> RuleSetBehavior {
        self.behavior
    }

    fn format(&self) -> RuleSetFormat {
        self.format
    }
}

#[async_trait]
impl Provider for RuleProviderImpl {
    fn name(&self) -> &str {
        self.fetcher.name()
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        self.fetcher.vehicle_type()
    }

    fn typ(&self) -> ProviderType {
        ProviderType::Rule
    }

    async fn initialize(&self) -> std::io::Result<()> {
        let ele = self.fetcher.initial().await.map_err(map_io_error)?;
        debug!("initializing rule provider {}", self.name());
        if let Some(updater) = self.fetcher.on_update.as_ref() {
            let f = updater.lock().await;
            f(ele).await; // Directly pass RuleContent
        }
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        let (ele, same) = self.fetcher.update().await.map_err(map_io_error)?;
        debug!("rule provider {} updated. same? {}", self.name(), same);
        if !same {
            if let Some(updater) = self.fetcher.on_update.as_ref() {
                let f = updater.lock().await;
                f(ele).await; // Directly pass RuleContent
            }
        }
        Ok(())
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send>> {
        let mut m: HashMap<String, Box<dyn ESerialize + Send>> = HashMap::new();

        m.insert("name".to_owned(), Box::new(self.name().to_string()));
        m.insert("type".to_owned(), Box::new(self.typ().to_string()));
        m.insert(
            "vehicleType".to_owned(),
            Box::new(self.vehicle_type().to_string()),
        );

        m.insert(
            "updatedAt".to_owned(),
            Box::new(self.fetcher.updated_at().await),
        );

        m.insert("behavior".to_owned(), Box::new(self.behavior().to_string()));
        m.insert("format".to_owned(), Box::new(self.format().to_string()));

        m
    }
}

// --- make_rules is needed for Yaml and Text formats ---
fn make_rules(
    behavior: RuleSetBehavior,
    rules: Vec<String>, // Input is Vec<String> for Yaml/Text
    mmdb: Arc<Mmdb>,
    geodata: Arc<GeoData>,
) -> Result<RuleContent, Error> {
    match behavior {
        RuleSetBehavior::Domain => {
            let s = make_domain_rules(rules)?;
            Ok(RuleContent::Domain(s.into()))
        }
        RuleSetBehavior::Ipcidr => {
            Ok(RuleContent::Ipcidr(Box::new(make_ip_cidr_rules(rules)?)))
        }
        RuleSetBehavior::Classical => Ok(RuleContent::Classical(
            make_classical_rules(rules, mmdb, geodata)?,
        )),
    }
}

fn make_domain_rules(rules: Vec<String>) -> Result<trie::StringTrie<bool>, Error> {
    let mut trie = trie::StringTrie::new();
    for rule in rules {
        trie.insert(&rule, Arc::new(true));
    }
    Ok(trie)
}

fn make_ip_cidr_rules(rules: Vec<String>) -> Result<CidrTrie, Error> {
    let mut trie = CidrTrie::new();
    for rule in rules {
        trie.insert(&rule);
    }
    Ok(trie)
}

fn make_classical_rules(
    rules: Vec<String>,
    mmdb: Arc<Mmdb>,
    geodata: Arc<GeoData>,
) -> Result<Vec<Box<dyn RuleMatcher>>, Error> {
    let mut rv = vec![];
    for rule in rules {
        let parts = rule.split(',').map(str::trim).collect::<Vec<&str>>();

        // the rule inside RULE-SET is slightly different from the rule in
        // config the target is always empty as it's holded in the
        // RULE-SET container let's parse it manually
        let rule_type = match parts.as_slice() {
            [proto, payload] => RuleType::new(proto, payload, "", None),
            [proto, payload, params @ ..] => {
                RuleType::new(proto, payload, "", Some(params.to_vec()))
            }
            _ => Err(Error::InvalidConfig(format!("invalid rule line: {}", rule))),
        }?;

        let rule_matcher =
            map_rule_type(rule_type, mmdb.clone(), geodata.clone(), None);
        rv.push(rule_matcher);
    }
    Ok(rv)
}
