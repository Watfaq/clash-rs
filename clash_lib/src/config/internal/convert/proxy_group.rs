use std::collections::HashMap;

use serde_yaml::Value;

use crate::{Error, config::proxy::OutboundProxy};

pub fn convert(
    before: Option<Vec<HashMap<String, Value>>>,
    proxy_names: &mut Vec<String>,
) -> Result<HashMap<String, OutboundProxy>, crate::Error> {
    before.unwrap_or_default().into_iter().try_fold(
        HashMap::<String, OutboundProxy>::new(),
        |mut rv, mapping| {
            let name = mapping.get("name").map(|x| x.clone());
            let group =
                OutboundProxy::ProxyGroup(mapping.try_into().map_err(|x| {
                    if let Some(name) = name {
                        Error::InvalidConfig(format!("proxy group: {name:#?}: {x}"))
                    } else {
                        Error::InvalidConfig("proxy group name missing".to_string())
                    }
                })?);
            proxy_names.push(group.name());
            rv.insert(group.name().to_string(), group);
            Ok::<HashMap<String, OutboundProxy>, Error>(rv)
        },
    )
}
