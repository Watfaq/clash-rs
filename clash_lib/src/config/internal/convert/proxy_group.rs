use std::collections::HashMap;

use serde_yaml::Value;

use crate::{config::proxy::OutboundProxy, Error};

pub fn concert(
    before: Option<Vec<HashMap<String, Value>>>,
    proxy_names: &mut Vec<String>,
) -> Result<HashMap<String, OutboundProxy>, crate::Error> {
    Ok(before.unwrap_or_default().into_iter().try_fold(
        HashMap::<String, OutboundProxy>::new(),
        |mut rv, mapping| {
            let group = OutboundProxy::ProxyGroup(
                mapping.clone().try_into().map_err(|x| {
                    if let Some(name) = mapping.get("name") {
                        Error::InvalidConfig(format!("proxy group: {name:#?}: {x}"))
                    } else {
                        Error::InvalidConfig("proxy group name missing".to_string())
                    }
                })?,
            );
            proxy_names.push(group.name());
            rv.insert(group.name().to_string(), group);
            Ok::<HashMap<String, OutboundProxy>, Error>(rv)
        },
    )?)
}
