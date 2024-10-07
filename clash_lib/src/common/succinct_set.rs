//! idea: https://github.com/openacid/succinct
//! impl: https://github.com/MetaCubeX/mihomo/blob/Meta/component/trie/domain_set.go
//! I have not idea what's going on here, just copy the code from above link.

use super::trie::StringTrie;

static COMPLEX_WILDCARD: u8 = b'+';
static WILDCARD: u8 = b'*';
static DOMAIN_STEP: u8 = b'.';

#[derive(Default)]
pub struct DomainSet {
    leaves: Vec<u64>,
    label_bit_map: Vec<u64>,
    labels: Vec<u8>,
    ranks: Vec<i32>,
    selects: Vec<i32>,
}

impl DomainSet {
    pub fn has(&self, key: &str) -> bool {}
}

impl DomainSet {
    fn init(&mut self) {}
}

struct QElt {
    s: usize,
    e: usize,
    col: usize,
}

impl<T> From<StringTrie<T>> for DomainSet {
    fn from(value: StringTrie<T>) -> Self {}
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test]
    fn test_domain_set() {
        let mut tree = super::StringTrie::new();
        let domains = vec![
            "baidu.com",
            "google.com",
            "www.google.com",
            "test.a.net",
            "test.a.oc",
            "Mijia Cloud",
            ".qq.com",
            "+.cn",
        ];

        for d in domains {
            tree.insert(d, Arc::new(true));
        }

        let set = super::DomainSet::from(tree);
        assert!(set.has("test.cn"));
        assert!(set.has("cn"));
        assert!(set.has("Mijia Cloud"));
        assert!(set.has("test.a.net"));
        assert!(set.has("www.qq.com"));
        assert!(set.has("google.com"));
        assert!(!set.has("qq.com"));
        assert!(!set.has("www.baidu.com"));
    }
}
