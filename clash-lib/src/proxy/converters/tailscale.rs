use crate::{
    Error,
    config::internal::proxy::OutboundTailscale,
    proxy::tailscale::{Handler, HandlerOptions},
};

impl TryFrom<OutboundTailscale> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTailscale) -> Result<Self, Self::Error> {
        if value.state_dir.is_some()
            || value.auth_key.is_some()
            || value.hostname.is_some()
            || value.control_url.is_some()
            || value.ephemeral
        {
            return Err(Error::InvalidConfig(
                "tailscale auth/runtime fields are not supported in this build. \
                 remove `state-dir`, `auth-key`, `hostname`, `control-url`, and \
                 `ephemeral` or enable a build with embedded tsnet integration"
                    .to_owned(),
            ));
        }
        Ok(Handler::new(HandlerOptions {
            name: value.name,
            state_dir: value.state_dir,
            auth_key: value.auth_key,
            hostname: value.hostname,
            control_url: value.control_url,
            ephemeral: value.ephemeral,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::Handler;
    use crate::config::internal::proxy::OutboundTailscale;

    #[test]
    fn tailscale_rejects_tsnet_auth_fields_without_embedded_tsnet() {
        let result = Handler::try_from(OutboundTailscale {
            name: "ts".to_owned(),
            auth_key: Some("tskey-auth-xxxx".to_owned()),
            ..Default::default()
        });

        assert!(result.is_err());
        let err = result.expect_err("expected invalid config error");
        assert!(
            err.to_string().contains("not supported in this build"),
            "unexpected error: {err}"
        );
    }
}
