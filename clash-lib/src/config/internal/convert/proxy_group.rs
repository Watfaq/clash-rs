use std::collections::HashMap;

use crate::{
    Error,
    config::proxy::{OutboundGroupProtocol, OutboundProxy},
};

pub fn convert(
    before: Option<Vec<OutboundGroupProtocol>>,
    proxy_names: &mut Vec<String>,
) -> Result<HashMap<String, OutboundProxy>, crate::Error> {
    before.unwrap_or_default().into_iter().try_fold(
        HashMap::<String, OutboundProxy>::new(),
        |mut rv, group_protocol| {
            let name = group_protocol.name().to_owned();
            if rv.contains_key(name.as_str()) {
                return Err(Error::InvalidConfig(format!(
                    "duplicated proxy group name: {name}"
                )));
            }
            let group = OutboundProxy::ProxyGroup(group_protocol);
            proxy_names.push(name.clone());
            rv.insert(name, group);
            Ok::<HashMap<String, OutboundProxy>, Error>(rv)
        },
    )
}
