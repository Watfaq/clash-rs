use crate::{
    app::router::rules::geodata::str_matcher::{Matcher, try_new_matcher},
    common::{
        geodata::geodata_proto::{Domain, domain::Type},
        trie,
    },
};
use std::sync::Arc;

pub trait DomainGroupMatcher: Send + Sync {
    fn apply(&self, domain: &str) -> bool;
}

pub struct SuccinctMatcherGroup {
    set: trie::StringTrie<()>,
    other_matchers: Vec<Box<dyn Matcher>>,
    not: bool,
}

impl SuccinctMatcherGroup {
    pub fn try_new(domains: Vec<Domain>, not: bool) -> Result<Self, crate::Error> {
        let mut set = trie::StringTrie::new();
        let mut other_matchers = Vec::new();
        for domain in domains {
            let t = Type::try_from(domain.r#type).map_err(|x| {
                crate::Error::InvalidConfig(format!("invalid domain type: {x}"))
            })?;

            match t {
                Type::Plain | Type::Regex => {
                    let matcher = try_new_matcher(domain.value, t)?;
                    other_matchers.push(matcher);
                }
                Type::Domain => {
                    let domain = format!("+.{}", domain.value);
                    set.insert(&domain, Arc::new(()));
                }
                Type::Full => {
                    set.insert(&domain.value, Arc::new(()));
                }
            }
        }
        Ok(SuccinctMatcherGroup {
            set,
            other_matchers,
            not,
        })
    }
}

impl DomainGroupMatcher for SuccinctMatcherGroup {
    fn apply(&self, domain: &str) -> bool {
        let mut is_matched = self.set.search(domain).is_some();
        if !is_matched {
            for matcher in &self.other_matchers {
                if matcher.matches(domain) {
                    is_matched = true;
                    break;
                }
            }
        }
        if self.not { !is_matched } else { is_matched }
    }
}
