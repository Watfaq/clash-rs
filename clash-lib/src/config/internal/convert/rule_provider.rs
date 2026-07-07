use std::collections::HashMap;

use crate::{
    common::utils::md5_str,
    config::{
        config::{
            FileRuleProvider, HttpRuleProvider, InlineRuleProvider, RuleProviderDef,
        },
        def,
    },
};

pub(super) fn convert(
    before: Option<HashMap<String, def::RuleProviderDef>>,
) -> HashMap<String, RuleProviderDef> {
    before
        .unwrap_or_default()
        .into_iter()
        .map(|(name, provider)| {
            let converted = match provider {
                def::RuleProviderDef::Http(h) => {
                    let path = h.path.unwrap_or_else(|| {
                        let key = &h.url;
                        let md5 = md5_str(key.as_bytes());
                        format!("rules/{md5}")
                    });
                    RuleProviderDef::Http(HttpRuleProvider {
                        url: h.url,
                        interval: h.interval,
                        behavior: h.behavior,
                        path,
                        format: h.format,
                        inline_rules: h.inline_rules,
                    })
                }
                def::RuleProviderDef::File(f) => {
                    RuleProviderDef::File(FileRuleProvider {
                        path: f.path,
                        interval: f.interval,
                        behavior: f.behavior,
                        format: f.format,
                        inline_rules: f.inline_rules,
                    })
                }
                def::RuleProviderDef::Inline(i) => {
                    let path = i.path.unwrap_or_else(|| {
                        let md5 = md5_str(name.as_bytes());
                        format!("rules/{md5}")
                    });
                    RuleProviderDef::Inline(InlineRuleProvider {
                        path,
                        behavior: i.behavior,
                        inline_rules: i.inline_rules,
                    })
                }
            };
            (name, converted)
        })
        .collect()
}
