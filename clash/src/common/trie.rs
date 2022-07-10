use std::{
    any::{self, Any},
    collections::HashMap,
    rc::Rc,
};

static DOMAIN_STEP: &str = ".";
static COMPLEX_WILDCARD: &str = "+";
static DOT_WILDCARD: &str = "";
static WILDCARD: &str = "*";

pub struct DomainTrie {
    root: Node,
}

struct Node {
    children: HashMap<String, Node>,
    data: Option<Rc<Box<dyn Any>>>,
}

impl Node {
    pub fn new() -> Self {
        Node {
            children: HashMap::new(),
            data: None,
        }
    }

    pub fn get_child(&self, s: &str) -> Option<&Self> {
        self.children.get(s)
    }

    pub fn has_child(&self, s: &str) -> bool {
        self.get_child(s).is_some()
    }

    pub fn add_child(&mut self, s: &str, child: Node) {
        self.children.insert(s.into(), child);
    }
}

impl DomainTrie {
    pub fn new() -> Self {
        DomainTrie { root: Node::new() }
    }

    pub fn insert(&mut self, domain: &str, data: Box<dyn Any>) -> bool {
        let (parts, valid) = valid_and_splic_domain(domain);
        if !valid {
            return false;
        }

        let mut parts = parts.unwrap();
        let data = Rc::new(data);

        match parts[0] {
            p if p == COMPLEX_WILDCARD => {
                self.insert_inner(&parts[1..].into(), data.clone());
                parts[0] = DOT_WILDCARD;
                self.insert_inner(&parts, data.clone());
            }
            _ => self.insert_inner(&parts, data),
        }

        return true;
    }

    pub fn search(&self, domain: &str) -> Option<&Node> {
        let (parts, valid) = valid_and_splic_domain(domain);
        if !valid {
            return None;
        }

        let parts = parts.unwrap();
        if parts[0] == "" {
            return None;
        }

        if let Some(n) = self.search_inner(&self.root, parts) {
            if n.data.is_some() {
                return Some(n);
            }
        }

        None
    }

    fn insert_inner(&mut self, parts: &Vec<&str>, data: Rc<Box<dyn Any>>) {
        let mut node = &mut self.root;

        for i in (0..parts.len()).rev() {
            let part = parts[i];
            if !node.has_child(part) {
                node.add_child(part, Node::new())
            }
        }

        node.data = Some(data);
    }

    fn search_inner<'a>(&'a self, node: &'a Node, parts: Vec<&str>) -> Option<&Node> {
        if parts.len() == 0 {
            return Some(node);
        }

        if let Some(c) = node.get_child(parts.last().unwrap()) {
            if let Some(n) = self.search_inner(c, parts[0..parts.len() - 1].into()) {
                if n.data.is_some() {
                    return Some(n);
                }
            }
        }

        if let Some(c) = node.get_child(WILDCARD) {
            if let Some(n) = self.search_inner(c, parts[0..parts.len() - 1].into()) {
                if n.data.is_some() {
                    return Some(n);
                }
            }
        }

        node.get_child(DOT_WILDCARD)
    }
}

pub fn valid_and_splic_domain(domain: &str) -> (Option<Vec<&str>>, bool) {
    if domain != "" && domain.ends_with(".") {
        return (None, false);
    }

    let parts: Vec<&str> = domain.split(DOMAIN_STEP).collect();
    if parts.len() == 1 {
        if parts[0] == "" {
            return (None, false);
        }
        return (Some(parts), true);
    }

    for p in parts.iter().skip(1) {
        if p == &"" {
            return (None, false);
        }
    }

    (Some(parts), true)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::DomainTrie;

    static LOCAL_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

    #[test]
    fn test_basic() {
        let mut tree = DomainTrie::new();

        let domains = vec!["example.com", "google.com", "localhost"];

        for d in domains {
            tree.insert(d, Box::new(LOCAL_IP));
        }

        let node = tree.search("example.com").expect("should be not nil");
        assert_eq!(
            node.data
                .as_ref()
                .expect("data nil")
                .downcast_ref::<Ipv4Addr>(),
            Some(&LOCAL_IP),
        );
        assert_eq!(tree.insert("", Box::new(LOCAL_IP)), true);
        assert!(tree.search("").is_none());
        assert!(tree.search("localhost").is_some());
        assert!(tree.search("www.google.com").is_none());
    }
}
