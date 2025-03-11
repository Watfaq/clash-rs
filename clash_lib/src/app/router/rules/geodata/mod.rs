use crate::{Error, app::router::RuleMatcher, session::Session};
use std::fmt::{Display, Formatter};

use crate::{
    app::router::rules::geodata::{
        attribute::{AndAttrMatcher, AttrMatcher},
        matcher_group::{DomainGroupMatcher, SuccinctMatcherGroup},
    },
    common::geodata::GeoData,
};

mod attribute;
mod matcher_group;
mod str_matcher;

// if country_code is empty, return None
// or will return the parsed **real** code and the attr list and if the code is
// negated
fn parse(country_code: &str) -> Option<(bool, String, Box<dyn AttrMatcher>)> {
    let country_code = country_code.trim().to_lowercase();
    let mut country_code = country_code.as_str();
    let mut not = false;

    if country_code.is_empty() {
        return None;
    }

    if country_code.as_bytes()[0] == b'!' {
        not = true;
        country_code = &country_code[1..];
    }
    let parts = country_code.split('@').collect::<Vec<&str>>();
    let code = parts[0].to_owned();
    let attrs = if parts.len() > 1 {
        parts[1].split(',').map(|x| x.to_owned()).collect()
    } else {
        Vec::new()
    };
    let attr_matcher = Box::new(AndAttrMatcher::from(attrs)) as _;

    Some((not, code, attr_matcher))
}

pub struct GeoSiteMatcher {
    pub country_code: String,
    pub target: String,
    pub matcher: Box<dyn DomainGroupMatcher>,
}

impl GeoSiteMatcher {
    pub fn new(
        country_code: String,
        target: String,
        loader: &GeoData,
    ) -> anyhow::Result<Self> {
        let (not, code, attr_matcher) =
            parse(&country_code).ok_or(Error::InvalidConfig(
                "invalid geosite matcher, country code is empty".to_owned(),
            ))?;
        let list =
            loader
                .get(&code)
                .cloned()
                .ok_or(Error::InvalidConfig(format!(
                    "geosite matcher, country code {} not found",
                    code
                )))?;
        let domains = list
            .domain
            .into_iter()
            .filter(|domain| attr_matcher.matches(domain))
            .collect::<Vec<_>>();

        let matcher_group: Box<dyn DomainGroupMatcher> =
            Box::new(SuccinctMatcherGroup::try_new(domains, not)?);
        Ok(Self {
            country_code,
            target,
            matcher: matcher_group,
        })
    }
}

impl Display for GeoSiteMatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GeoSite({})", self.country_code)
    }
}

impl RuleMatcher for GeoSiteMatcher {
    fn apply(&self, sess: &Session) -> bool {
        match &sess.destination {
            crate::session::TargetAddr::Socket(_) => false,
            crate::session::TargetAddr::Domain(domain, _) => {
                self.matcher.apply(domain.as_str())
            }
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.country_code.clone()
    }

    fn type_name(&self) -> &str {
        "GeoSite"
    }
}
