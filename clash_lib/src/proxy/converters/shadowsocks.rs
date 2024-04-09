use crate::{
    config::internal::proxy::OutboundShadowsocks,
    proxy::{
        shadowsocks::{Handler, HandlerOptions, OBFSOption},
        AnyOutboundHandler
    },
    Error,
};

impl TryFrom<OutboundShadowsocks> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(value: OutboundShadowsocks) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundShadowsocks> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(s: &OutboundShadowsocks) -> Result<Self, Self::Error> {
        let h = Handler::new(HandlerOptions {
            name: s.name.to_owned(),
            common_opts: s.common_opts.clone(),
            server: s.server.to_owned(),
            port: s.port,
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
