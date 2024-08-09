use std::collections::HashMap;

use crate::{
    config::internal::proxy::OutboundShadowsocks,
    proxy::{
        shadowsocks::{
            Handler, HandlerOptions, OBFSOption, ShadowTlsOption, SimpleOBFSMode,
            SimpleOBFSOption, V2RayOBFSOption,
        },
        CommonOption,
    },
    Error,
};

impl TryFrom<OutboundShadowsocks> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundShadowsocks) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundShadowsocks> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundShadowsocks) -> Result<Self, Self::Error> {
        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: CommonOption {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.to_owned(),
            cipher: s.cipher.to_owned(),
            plugin_opts: match &s.plugin {
                Some(plugin) => match plugin.as_str() {
                    "obfs" => s
                        .plugin_opts
                        .clone()
                        .ok_or(Error::InvalidConfig(
                            "plugin_opts is required for plugin obfs".to_owned(),
                        ))?
                        .try_into()
                        .map(OBFSOption::Simple)
                        .ok(),
                    "v2ray-plugin" => s
                        .plugin_opts
                        .clone()
                        .ok_or(Error::InvalidConfig(
                            "plugin_opts is required for plugin obfs".to_owned(),
                        ))?
                        .try_into()
                        .map(OBFSOption::V2Ray)
                        .ok(),
                    "shadow-tls" => s
                        .plugin_opts
                        .clone()
                        .ok_or(Error::InvalidConfig(
                            "plugin_opts is required for plugin obfs".to_owned(),
                        ))?
                        .try_into()
                        .map(OBFSOption::ShadowTls)
                        .ok(),
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "unsupported plugin: {}",
                            plugin
                        )));
                    }
                },
                None => None,
            },
            udp: s.udp,
        });
        Ok(h)
    }
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for SimpleOBFSOption {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

        match mode {
            "http" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Http,
                host: host.to_owned(),
            }),
            "tls" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Tls,
                host: host.to_owned(),
            }),
            _ => Err(Error::InvalidConfig(format!("invalid obfs mode: {}", mode))),
        }
    }
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for V2RayOBFSOption {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

        if mode != "websocket" {
            return Err(Error::InvalidConfig(format!(
                "invalid obfs mode: {}",
                mode
            )));
        }

        let path = value
            .get("path")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs path is required".to_owned()))?;
        let mux = value.get("mux").and_then(|x| x.as_bool()).unwrap_or(false);
        let tls = value.get("tls").and_then(|x| x.as_bool()).unwrap_or(false);
        let skip_cert_verify = value
            .get("skip-cert-verify")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);

        let mut headers = HashMap::new();
        if let Some(h) = value.get("headers") {
            if let Some(h) = h.as_mapping() {
                for (k, v) in h {
                    if let (Some(k), Some(v)) = (k.as_str(), v.as_str()) {
                        headers.insert(k.to_owned(), v.to_owned());
                    }
                }
            }
        }

        Ok(V2RayOBFSOption {
            mode: mode.to_owned(),
            host: host.to_owned(),
            path: path.to_owned(),
            tls,
            headers,
            skip_cert_verify,
            mux,
        })
    }
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for ShadowTlsOption {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let password = value
            .get("password")
            .and_then(|x| x.as_str().to_owned())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;
        let strict = value
            .get("strict")
            .and_then(|x| x.as_bool())
            .unwrap_or(true);

        Ok(Self {
            host: host.to_string(),
            password: password.to_string(),
            strict,
        })
    }
}
