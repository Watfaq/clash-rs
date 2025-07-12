use crate::common::geodata::geodata_proto::domain::Type;

pub trait Matcher: Send + Sync {
    fn matches(&self, url: &str) -> bool;
}

pub struct FullMatcher(pub String);

impl Matcher for FullMatcher {
    fn matches(&self, url: &str) -> bool {
        self.0 == url
    }
}

pub struct SubStrMatcher(pub String);

impl Matcher for SubStrMatcher {
    fn matches(&self, url: &str) -> bool {
        url.contains(&self.0)
    }
}

pub struct DomainMatcher(pub String);

impl Matcher for DomainMatcher {
    fn matches(&self, url: &str) -> bool {
        let pattern = &self.0;
        if !url.ends_with(pattern) {
            return false;
        }
        if pattern.len() == url.len() {
            return true;
        }
        let prefix_idx_end = url.len() as i32 - pattern.len() as i32 - 1;
        if prefix_idx_end < 0 {
            return false;
        }
        url.as_bytes()[prefix_idx_end as usize] == b'.'
    }
}

pub struct RegexMatcher(regex::Regex);

impl Matcher for RegexMatcher {
    fn matches(&self, url: &str) -> bool {
        self.0.is_match(url)
    }
}

pub fn try_new_matcher(
    domain: String,
    t: Type,
) -> Result<Box<dyn Matcher>, crate::Error> {
    Ok(match t {
        Type::Plain => Box::new(SubStrMatcher(domain)),
        Type::Regex => {
            Box::new(RegexMatcher(regex::Regex::new(&domain).map_err(|x| {
                crate::Error::InvalidConfig(format!("invalid regex: {x}"))
            })?))
        }
        Type::Domain => Box::new(DomainMatcher(domain)),
        Type::Full => Box::new(FullMatcher(domain)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matchers() {
        let full_matcher = FullMatcher("https://google.com".to_string());
        assert!(full_matcher.matches("https://google.com"));
        assert!(!full_matcher.matches("https://www.google.com"));

        let sub_str_matcher = SubStrMatcher("google".to_string());
        assert!(sub_str_matcher.matches("https://www.google.com"));
        assert!(!sub_str_matcher.matches("https://www.youtube.com"));

        let domain_matcher = DomainMatcher("google.com".to_string());
        assert!(domain_matcher.matches("https://www.google.com"));
        assert!(!domain_matcher.matches("https://www.fakegoogle.com"));
        assert!(!domain_matcher.matches("https://wwwgoogle.com"));

        let regex_matcher =
            RegexMatcher(regex::Regex::new(r".*google\..*").unwrap());
        assert!(regex_matcher.matches("https://www.google.com"));
        assert!(regex_matcher.matches("https://www.fakegoogle.com"));
        assert!(!regex_matcher.matches("https://goo.gle.com"));
    }
}
