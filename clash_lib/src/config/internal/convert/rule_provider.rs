use std::collections::HashMap;

use serde::{Deserialize as _, de::value::MapDeserializer};
use serde_yaml::Value;

use crate::{
    Error,
    common::utils::md5_str,
    config::{config::RuleProviderDef, proxy::map_serde_error},
};

pub(super) fn convert(
    before: Option<HashMap<String, HashMap<String, Value>>>,
) -> HashMap<String, RuleProviderDef> {
    before
        .map(|m| {
            m.into_iter()
                .try_fold(HashMap::new(), |mut rv, (name, mut body)| {
                    body.insert(
                        "name".to_owned(),
                        serde_yaml::Value::String(name.clone()),
                    );

                    // Set default values if not present
                    if !body.contains_key("interval") {
                        body.insert(
                            "interval".to_owned(),
                            serde_yaml::Value::Number(0u64.into()),
                        );
                    }
                    if !body.contains_key("path") {
                        // Prefer url if present, else use name
                        let key = body
                            .get("url")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&name);
                        let md5 = md5_str(key.as_bytes());
                        let path = format!("rules/{}", md5);
                        body.insert(
                            "path".to_owned(),
                            serde_yaml::Value::String(path),
                        );
                    }

                    let provider = RuleProviderDef::try_from(body).map_err(|x| {
                        Error::InvalidConfig(format!(
                            "invalid rule provider {name}: {x}"
                        ))
                    })?;
                    rv.insert(name, provider);
                    Ok::<HashMap<std::string::String, RuleProviderDef>, Error>(rv)
                })
                .expect("proxy provider parse error")
        })
        .unwrap_or_default()
}

impl TryFrom<HashMap<String, Value>> for RuleProviderDef {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "rule provider name is required".to_owned(),
            ))?
            .to_owned();

        RuleProviderDef::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}
