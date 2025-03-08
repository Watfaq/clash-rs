use std::collections::HashMap;

use serde::{Deserialize, de::value::MapDeserializer};
use serde_yaml::Value;

use crate::{
    common::auth,
    config::{
        def,
        internal::{
            proxy::{OutboundProxy, PROXY_DIRECT, PROXY_REJECT},
            rule::RuleType,
        },
    },
};
use watfaq_error::{ErrContext, Error, Result, anyhow};

mod dns;
mod general;
mod listener;
mod proxy_group;
mod rule_provider;
mod tun;

use super::{
    config::{self, BindAddress, Profile},
    proxy::{
        OutboundGroupProtocol, OutboundProxyProtocol, OutboundProxyProviderDef,
    },
};

impl TryFrom<def::Config> for config::Config {
    type Error = Error;

    fn try_from(value: def::Config) -> Result<Self> {
        convert(value)
    }
}

pub(super) fn convert(mut c: def::Config) -> Result<config::Config> {
    let mut proxy_names =
        vec![String::from(PROXY_DIRECT), String::from(PROXY_REJECT)];

    if c.allow_lan.unwrap_or(false) {
        c.bind_address = BindAddress::all()
    } else {
        c.bind_address = BindAddress::local()
    }

    config::Config {
        general: general::convert(&c)?,
        dns: dns::convert(&c)?,
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
            .map(|x| x.parse::<RuleType>().context("parse RuleType Error"))
            .collect::<Result<Vec<_>>>()?,
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
                    return Err(anyhow!("duplicated proxy name: {name}"));
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
                            .with_context(|| {
                                format!("invalid proxy provider {name}")
                            })?;
                        rv.insert(name, provider);
                        Ok::<HashMap<String, OutboundProxyProviderDef>, Error>(rv)
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

    fn try_from(mapping: HashMap<String, Value>) -> Result<OutboundGroupProtocol> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("missing field `name` in outbound proxy grouop"))?
            .to_owned();
        let res = OutboundGroupProtocol::deserialize(MapDeserializer::new(
            mapping.into_iter(),
        ))?;
        Ok(res)
    }
}
