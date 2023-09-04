use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
};

use crate::{config::internal::proxy::OutboundGroupProtocol, Error};

// copy paste from https://github.com/Dreamacro/clash/blob/6a661bff0c185f38c4bd9d21c91a3233ba5fdb97/config/utils.go#L21
pub fn proxy_groups_dag_sort(groups: &mut Vec<OutboundGroupProtocol>) -> Result<(), Error> {
    struct Node {
        in_degree: i32,

        // could be either group/proxy
        proto: Option<OutboundGroupProtocol>,

        outdegree: i32,

        from: Vec<String>,
    }

    let mut graph: HashMap<String, RefCell<Node>> = HashMap::new();

    for group in groups.iter() {
        let group_name = group.name().to_owned();

        let node = graph.get(&group_name);

        if let Some(node) = node {
            if node.borrow().proto.is_some() {
                return Err(Error::InvalidConfig(format!(
                    "duplicate proxy group name: {}",
                    group_name
                )));
            } else {
                node.borrow_mut().proto = Some(group.clone());
            }
        } else {
            graph.insert(
                group_name.clone(),
                RefCell::new(Node {
                    in_degree: 0,
                    proto: Some(group.clone()),
                    outdegree: 0,
                    from: vec![],
                }),
            );
        }

        if let Some(proxies) = group.proxies() {
            for proxy in proxies {
                if let Some(node) = graph.get(proxy) {
                    node.borrow_mut().in_degree += 1;
                } else {
                    graph.insert(
                        proxy.clone(),
                        RefCell::new(Node {
                            in_degree: 1,
                            proto: None,
                            outdegree: 0,
                            from: vec![],
                        }),
                    );
                }
            }
        }
    }

    let mut index = 0;
    let mut queue = VecDeque::new();

    for (name, node) in graph.iter() {
        if node.borrow_mut().in_degree == 0 {
            queue.push_back(name.clone());
        }
    }

    let group_len = groups.len();

    while !queue.is_empty() {
        let name = queue.pop_front().unwrap().to_owned();
        let node = graph
            .get(&name)
            .expect(format!("node {} not found", &name).as_str());

        if node.borrow().proto.is_some() {
            index += 1;
            groups[group_len - index] = node.borrow_mut().proto.take().unwrap();
            if groups[group_len - index].proxies().is_none() {
                graph.remove(&name);
                continue;
            }

            for proxy in groups[group_len - index].proxies().unwrap() {
                let node = graph.get(proxy.as_str()).unwrap();
                node.borrow_mut().in_degree -= 1;
                if node.borrow().in_degree == 0 {
                    queue.push_back(proxy.clone());
                }
            }
        }

        graph.remove(&name);
    }

    if graph.len() == 0 {
        return Ok(());
    }

    for (name, node) in graph.iter() {
        if node.borrow().proto.is_none() {
            continue;
        }

        if node.borrow().proto.as_ref().unwrap().proxies().is_none() {
            continue;
        }

        let proxies = node
            .borrow()
            .proto
            .as_ref()
            .unwrap()
            .proxies()
            .unwrap()
            .clone();

        for proxy in proxies.iter() {
            node.borrow_mut().outdegree += 1;
            graph
                .get(proxy)
                .unwrap()
                .borrow_mut()
                .from
                .push(name.to_owned());
        }
    }

    let mut queue = vec![];
    for (name, node) in graph.iter() {
        if node.borrow_mut().outdegree == 0 {
            queue.push(name.to_owned());
        }
    }

    while queue.len() > 0 {
        let name = queue.first().unwrap().to_owned();
        let node = graph.get(&name).unwrap();

        let parents = node.borrow().from.clone();

        for parent in parents {
            graph.get(parent.as_str()).unwrap().borrow_mut().outdegree -= 1;
            if graph.get(parent.as_str()).unwrap().borrow_mut().outdegree == 0 {
                queue.push(parent);
            }
        }

        graph.remove(&name);

        queue.remove(0);
    }

    let looped_groups: Vec<String> = graph.keys().map(|s| s.to_owned()).collect();

    return Err(Error::InvalidConfig(format!(
        "loop detected in proxy groups: {:?}",
        looped_groups
    )));
}

#[cfg(test)]
mod tests {
    use crate::config::internal::proxy::{
        OutboundGroupFallback, OutboundGroupLoadBalance, OutboundGroupProtocol, OutboundGroupRelay,
        OutboundGroupSelect, OutboundGroupUrlTest,
    };

    #[test]
    fn test_proxy_groups_dag_sort_ok() {
        let g1 = OutboundGroupRelay {
            name: "relay".to_owned(),
            proxies: Some(vec![
                "ss".to_owned(),
                "auto".to_owned(),
                "fallback-auto".to_owned(),
                "load-balance".to_owned(),
                "select".to_owned(),
                "DIRECT".to_owned(),
            ]),
            ..Default::default()
        };
        let g2 = OutboundGroupUrlTest {
            name: "auto".to_owned(),
            proxies: Some(vec!["ss".to_owned(), "DIRECT".to_owned()]),
            ..Default::default()
        };
        let g3 = OutboundGroupFallback {
            name: "fallback-auto".to_owned(),
            proxies: Some(vec!["ss".to_owned(), "DIRECT".to_owned()]),
            ..Default::default()
        };
        let g4 = OutboundGroupLoadBalance {
            name: "load-balance".to_owned(),
            proxies: Some(vec!["ss".to_owned(), "DIRECT".to_owned()]),
            ..Default::default()
        };
        let g5 = OutboundGroupSelect {
            name: "select".to_owned(),
            proxies: Some(vec![
                "ss".to_owned(),
                "DIRECT".to_owned(),
                "REJECT".to_owned(),
            ]),
            ..Default::default()
        };

        let mut groups = vec![
            OutboundGroupProtocol::Relay(g1),
            OutboundGroupProtocol::UrlTest(g2),
            OutboundGroupProtocol::Fallback(g3),
            OutboundGroupProtocol::LoadBalance(g4),
            OutboundGroupProtocol::Select(g5),
        ];

        super::proxy_groups_dag_sort(&mut groups).unwrap();

        assert_eq!(groups.last().unwrap().name(), "relay");
    }

    #[test]
    fn test_proxy_groups_dag_sort_cycle() {
        let g1 = OutboundGroupRelay {
            name: "relay".to_owned(),
            proxies: Some(vec![
                "ss".to_owned(),
                "auto".to_owned(),
                "fallback-auto".to_owned(),
            ]),
            ..Default::default()
        };
        let g2 = OutboundGroupUrlTest {
            name: "auto".to_owned(),
            proxies: Some(vec![
                "ss".to_owned(),
                "DIRECT".to_owned(),
                "cycle".to_owned(),
            ]),
            ..Default::default()
        };
        let g3 = OutboundGroupFallback {
            name: "cycle".to_owned(),
            proxies: Some(vec![
                "ss".to_owned(),
                "DIRECT".to_owned(),
                "relay".to_owned(),
            ]),
            ..Default::default()
        };

        let mut groups = vec![
            OutboundGroupProtocol::Relay(g1),
            OutboundGroupProtocol::UrlTest(g2),
            OutboundGroupProtocol::Fallback(g3),
        ];

        let e = super::proxy_groups_dag_sort(&mut groups).unwrap_err();
        assert!(e.to_string().contains("loop detected in proxy groups"));
    }
}
