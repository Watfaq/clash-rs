use std::collections::HashMap;

use serde::{Deserialize, de::value::MapDeserializer};
use serde_yaml::Value;

use crate::{
    Error,
    common::auth,
    config::{
        def,
        internal::{
            proxy::{OutboundProxy, PROXY_DIRECT, PROXY_REJECT},
            rule::RuleType,
        },
    },
};

mod general;
mod listener;
mod proxy_group;
mod rule_provider;
mod tun;

use super::{
    config::{self, BindAddress, Profile},
    proxy::{
        OutboundGroupProtocol, OutboundProxyProtocol, OutboundProxyProviderDef,
        map_serde_error,
    },
};

impl TryFrom<def::Config> for config::Config {
    type Error = crate::Error;

    fn try_from(value: def::Config) -> Result<Self, Self::Error> {
        convert(value)
    }
}

pub(super) fn convert(mut c: def::Config) -> Result<config::Config, crate::Error> {
    let mut proxy_names =
        vec![String::from(PROXY_DIRECT), String::from(PROXY_REJECT)];

    if c.allow_lan.unwrap_or(false) {
        c.bind_address = BindAddress::all()
    } else {
        c.bind_address = BindAddress::local()
    }

    config::Config {
        general: general::convert(&c)?,
        dns: (&c).try_into()?,
        experimental: c.experimental.take(),
        tun: tun::convert(c.tun.take())?,
        profile: Profile {
            store_selected: c.profile.store_selected,
        },
        rules: c
            .rule
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|x| {
                x.parse::<RuleType>()
                    .map_err(|x| Error::InvalidConfig(x.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?,
        rule_providers: rule_provider::convert(c.rule_provider.take()),
        users: c
            .authentication
            .clone()
            .into_iter()
            .map(|u| {
                let mut parts = u.splitn(2, ':');
                let username = parts.next().unwrap().to_string();
                let password = parts.next().unwrap_or("").to_string();
                auth::User::new(username, password)
            })
            .collect(),
        proxies: c.proxy.take().unwrap_or_default().into_iter().try_fold(
            HashMap::from([
                (
                    String::from(PROXY_DIRECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Direct),
                ),
                (
                    String::from(PROXY_REJECT),
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::Reject),
                ),
            ]),
            |mut rv, x| {
                let proxy =
                    OutboundProxy::ProxyServer(OutboundProxyProtocol::try_from(x)?);
                let name = proxy.name();
                if rv.contains_key(name.as_str()) {
                    return Err(Error::InvalidConfig(format!(
                        "duplicated proxy name: {name}"
                    )));
                }
                proxy_names.push(name.clone());
                rv.insert(name, proxy);
                Ok(rv)
            },
        )?,
        proxy_groups: proxy_group::concert(c.proxy_group.take(), &mut proxy_names)?,
        proxy_names,
        proxy_providers: c
            .proxy_provider
            .take()
            .map(|m| {
                m.into_iter()
                    .try_fold(HashMap::new(), |mut rv, (name, mut body)| {
                        body.insert(
                            "name".to_owned(),
                            serde_yaml::Value::String(name.clone()),
                        );
                        let provider = OutboundProxyProviderDef::try_from(body)
                            .map_err(|x| {
                                Error::InvalidConfig(format!(
                                    "invalid proxy provider {name}: {x}"
                                ))
                            })?;
                        rv.insert(name, provider);
                        Ok::<
                            HashMap<std::string::String, OutboundProxyProviderDef>,
                            Error,
                        >(rv)
                    })
                    .expect("proxy provider parse error")
            })
            .unwrap_or_default(),
        listeners: listener::convert(c.listener.take(), &c)?,
    }
    .validate()
}

impl TryFrom<HashMap<String, Value>> for OutboundGroupProtocol {
    type Error = Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy grouop".to_owned(),
            ))?
            .to_owned();
        OutboundGroupProtocol::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}
