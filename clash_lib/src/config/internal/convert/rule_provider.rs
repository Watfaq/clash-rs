use std::collections::HashMap;

use serde::{Deserialize as _, de::value::MapDeserializer};
use serde_yaml::Value;

use crate::{
    Error,
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
