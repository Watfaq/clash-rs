use crate::{
    config::internal::proxy::OutboundTailscale,
    proxy::tailscale::{Handler, HandlerOptions},
};

impl TryFrom<OutboundTailscale> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTailscale) -> Result<Self, Self::Error> {
        Ok(Handler::new(HandlerOptions {
            name: value.name,
            state_dir: value.state_dir,
            auth_key: value.auth_key,
            hostname: value.hostname,
            control_url: value.control_url,
            client_name: value.client_name,
            ephemeral: value.ephemeral,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::Handler;
    use crate::config::internal::proxy::OutboundTailscale;

    #[test]
    fn tailscale_accepts_tsnet_auth_fields() {
        let result = Handler::try_from(OutboundTailscale {
            name: "ts".to_owned(),
            auth_key: Some("tskey-auth-xxxx".to_owned()),
            client_name: Some("my-app".to_owned()),
            ..Default::default()
        });

        assert!(result.is_ok());
    }
}
