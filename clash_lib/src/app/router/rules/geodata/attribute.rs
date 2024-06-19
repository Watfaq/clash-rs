use crate::common::geodata::geodata_proto;

pub trait AttrMatcher {
    fn matches(&self, domain: &geodata_proto::Domain) -> bool;
}

pub struct BooleanAttrMatcher(pub String);

impl AttrMatcher for BooleanAttrMatcher {
    fn matches(&self, domain: &geodata_proto::Domain) -> bool {
        for attr in &domain.attribute {
            if attr.key.eq_ignore_ascii_case(&self.0) {
                return true;
            }
        }
        false
    }
}

impl From<String> for BooleanAttrMatcher {
    fn from(s: String) -> Self {
        BooleanAttrMatcher(s)
    }
}

// logical AND of multiple attribute matchers
pub struct AndAttrMatcher {
    list: Vec<Box<dyn AttrMatcher>>,
}

impl From<Vec<String>> for AndAttrMatcher {
    fn from(list: Vec<String>) -> Self {
        AndAttrMatcher {
            list: list
                .into_iter()
                .map(|s| Box::new(BooleanAttrMatcher(s)) as Box<dyn AttrMatcher>)
                .collect(),
        }
    }
}

impl AttrMatcher for AndAttrMatcher {
    fn matches(&self, domain: &geodata_proto::Domain) -> bool {
        for matcher in &self.list {
            if !matcher.matches(domain) {
                return false;
            }
        }
        true
    }
}
