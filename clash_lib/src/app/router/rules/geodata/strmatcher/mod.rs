pub trait Matcher: Send + Sync{
    fn matches(&self, url: &str) -> bool;

    fn to_string(&self) -> String;
}

pub struct FullMatcher(pub String);

impl Matcher for FullMatcher {
    fn matches(&self, url: &str) -> bool {
        self.0 == url
    }

    fn to_string(&self) -> String {
        self.0.clone()
    }
}

pub struct SubStrMatcher(pub String);

impl Matcher for SubStrMatcher {
    fn matches(&self, url: &str) -> bool {
        url.contains(&self.0)
    }

    fn to_string(&self) -> String {
        self.0.clone()
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

    fn to_string(&self) -> String {
        self.0.clone()
    }
}

pub struct RegexMatcher(regex::Regex);

impl Matcher for RegexMatcher {
    fn matches(&self, url: &str) -> bool {
        self.0.is_match(url)
    }

    fn to_string(&self) -> String {
        self.0.as_str().to_string()
    }
}

use super::geodata_proto::domain::Type;

pub fn try_new_matcher(domain: String, t: Type) -> Result<Box<dyn Matcher>, anyhow::Error> {
    Ok(match t {
        Type::Plain => Box::new(SubStrMatcher(domain)),
        Type::Regex => Box::new(RegexMatcher(regex::Regex::new(&domain)?)),
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
        assert_eq!(full_matcher.matches("https://google.com"), true);
        assert_eq!(full_matcher.matches("https://www.google.com"), false);

        let sub_str_matcher = SubStrMatcher("google".to_string());
        assert_eq!(sub_str_matcher.matches("https://www.google.com"), true);
        assert_eq!(sub_str_matcher.matches("https://www.youtube.com"), false);

        let domain_matcher = DomainMatcher("google.com".to_string());
        assert_eq!(domain_matcher.matches("https://www.google.com"), true);
        assert_eq!(domain_matcher.matches("https://www.fakegoogle.com"), false);
        assert_eq!(domain_matcher.matches("https://wwwgoogle.com"), false);

        let regex_matcher = RegexMatcher(regex::Regex::new(r".*google\..*").unwrap());
        assert_eq!(regex_matcher.matches("https://www.google.com"), true);
        assert_eq!(regex_matcher.matches("https://www.fakegoogle.com"), true);
        assert_eq!(regex_matcher.matches("https://goo.gle.com"), false);
    }
}