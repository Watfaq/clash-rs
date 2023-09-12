use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{
    app::{
        remote_content_manager::providers::{
            fetcher::Fetcher, Provider, ThreadSafeProviderVehicle,
        },
        router::RuleMatcher,
    },
    common::trie,
    config::internal::rule::RuleType,
    session::Session,
    Error,
};

use super::cidr_trie::CidrTrie;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    pub payload: Vec<String>,
}

pub enum RuleSetBehavior {
    Domain,
    IPCIDR,
    Classical,
}

enum RuleContent {
    Domain(trie::StringTrie<bool>),
    IPCIDR(CidrTrie),
    Classical(Vec<Box<dyn RuleMatcher>>),
}

struct Inner {
    content: RuleContent,
    count: usize,
}

#[async_trait]
pub trait RuleProvider: Provider {
    async fn rules(&self) -> Vec<String>;
    async fn search(&self, sess: &Session) -> bool;
    async fn rule_count(&self) -> usize;
    fn behavior(&self) -> RuleSetBehavior;
}

pub struct RuleProviderImpl {
    fetcher: Fetcher<
        Box<dyn Fn(RuleContent) -> BoxFuture<'static, ()> + Send + Sync + 'static>,
        Box<dyn Fn(&[u8]) -> anyhow::Result<RuleContent> + Send + Sync + 'static>,
    >,
    inner: std::sync::Arc<tokio::sync::RwLock<Inner>>,
    behavior: RuleSetBehavior,
}

impl RuleProviderImpl {
    pub fn new(
        name: String,
        behovior: RuleSetBehavior,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
    ) -> Self {
        let inner = Arc::new(tokio::sync::RwLock::new(Inner {
            content: match behovior {
                RuleSetBehavior::Domain => RuleContent::Domain(trie::StringTrie::new()),
                RuleSetBehavior::IPCIDR => RuleContent::IPCIDR(CidrTrie::new()),
                RuleSetBehavior::Classical => RuleContent::Classical(vec![]),
            },
            count: 0,
        }));

        let inner_clone = inner.clone();

        let n = name.clone();
        let updater: Box<dyn Fn(RuleContent) -> BoxFuture<'static, ()> + Send + Sync + 'static> =
            Box::new(move |input: RuleContent| -> BoxFuture<'static, ()> {
                let n = n.clone();
                let inner: Arc<tokio::sync::RwLock<Inner>> = inner_clone.clone();
                Box::pin(async move {
                    let mut inner = inner.write().await;
                    trace!("updated rules for: {}", n);
                    inner.content = input;
                })
            });

        let n = name.clone();
        let parser: Box<dyn Fn(&[u8]) -> anyhow::Result<RuleContent> + Send + Sync + 'static> =
            Box::new(move |input: &[u8]| -> anyhow::Result<RuleContent> {
                let scheme: ProviderScheme = serde_yaml::from_slice(input).map_err(|x| {
                    Error::InvalidConfig(format!("proxy provider parse error {}: {}", n, x))
                })?;
                let rules = make_rules(behovior, scheme.payload)?;
                Ok(rules)
            });
    }
}

fn make_rules(behavior: RuleSetBehavior, rules: Vec<String>) -> Result<RuleContent, Error> {
    match behavior {
        RuleSetBehavior::Domain => todo!(),
        RuleSetBehavior::IPCIDR => todo!(),
        RuleSetBehavior::Classical => todo!(),
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

fn make_classical_rules(rules: Vec<String>) -> Result<Vec<Box<dyn RuleMatcher>>, Error> {
    let mut rv = vec![];
    for rule in rules {
        let rule_type = rule.parse::<RuleType>()?;
        rv.push(matcher);
    }
    Ok(rv)
}
